/*
 * Copyright 2020-2026 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Tests that drive the TA through ta_invoke_command_handler() with hand-built parameters, bypassing the
// client library validation. Each scenario runs in a forked child so that a hang in the TA is reported as a
// test failure instead of hanging the test binary.

#include "sa_rights.h"
#include "sa_ta_types.h"
#include "ta.h"
#include "gtest/gtest.h"
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <poll.h>
#include <sys/wait.h>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace {
    const int CHILD_TIMEOUT_MS = 10000;
    const uint32_t INVALID_BUFFER_TYPE = 0x7f;

    // Progress steps reported by the child.
    const uint8_t STEP_CIPHER_READY = 1;
    const uint8_t STEP_PROCESS_REJECTED = 2;
    const uint8_t STEP_CLOSING_SESSION = 3;
    const uint8_t STEP_SESSION_CLOSED = 4;

    struct child_result {
        int last_step = 0;  // last progress step the child reported
        bool hung = false;  // the child did not exit within CHILD_TIMEOUT_MS and was killed
        int exit_code = -1; // the child's exit status, or -1 if it did not exit normally
    };

    // Runs body in a forked child. body reports progress by writing step numbers to fd and returns the child's exit
    // status.
    template<typename F>
    child_result run_in_child(F body) {
        child_result result;
        int fds[2];
        // The pipe is only shared with a forked child that never calls exec, so O_CLOEXEC (pipe2) is not needed
        // and pipe2 is not available on all supported platforms.
        if (pipe(fds) != 0) // NOLINT(android-cloexec-pipe)
            return result;

        fflush(nullptr);
        pid_t const pid = fork();
        if (pid == 0) {
            close(fds[0]);
            int const rc = body(fds[1]);
            _exit(rc);
        }

        close(fds[1]);
        int elapsed = 0;
        while (true) {
            struct pollfd pfd = {fds[0], POLLIN, 0};
            int const ready = poll(&pfd, 1, 100);
            if (ready > 0) {
                uint8_t step;
                ssize_t const n = read(fds[0], &step, 1);
                if (n == 1) {
                    result.last_step = step;
                    continue;
                }

                if (n == 0)
                    break; // child closed the pipe (exited)
            } else {
                elapsed += 100;
            }

            int status;
            if (waitpid(pid, &status, WNOHANG) == pid) {
                result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                close(fds[0]);
                return result;
            }

            if (elapsed >= CHILD_TIMEOUT_MS) {
                result.hung = true;
                kill(pid, SIGKILL);
                break;
            }
        }

        int status;
        waitpid(pid, &status, 0);
        if (!result.hung)
            result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        close(fds[0]);
        return result;
    }

    void step(int fd, uint8_t value) {
        if (write(fd, &value, 1) != 1) {
            _exit(100);
        }
    }

    sa_status invoke(
            void* session,
            SA_COMMAND_ID command_id,
            uint32_t t0,
            void* p0,
            size_t s0,
            uint32_t t1 = TEEC_NONE,
            void* p1 = nullptr,
            size_t s1 = 0,
            uint32_t t2 = TEEC_NONE,
            void* p2 = nullptr,
            size_t s2 = 0,
            uint32_t t3 = TEEC_NONE,
            void* p3 = nullptr,
            size_t s3 = 0) {
        uint32_t param_types[NUM_TA_PARAMS] = {t0, t1, t2, t3};
        ta_param params[NUM_TA_PARAMS] = {{p0, s0}, {p1, s1}, {p2, s2}, {p3, s3}};
        return ta_invoke_command_handler(session, command_id, param_types, params);
    }

    sa_status import_key(
            void* session,
            sa_key* key,
            uint32_t key_format,
            std::vector<uint8_t>& in) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        sa_key_import_s key_import = {API_VERSION, INVALID_HANDLE, key_format, 0};
        sa_status const status = invoke(session, SA_KEY_IMPORT,
                TEEC_MEMREF_TEMP_INOUT, &key_import, sizeof(key_import),
                TEEC_MEMREF_TEMP_INPUT, in.data(), in.size(),
                TEEC_MEMREF_TEMP_INPUT, &rights, sizeof(rights));
        *key = key_import.key;
        return status;
    }

    sa_status cipher_init(
            void* session,
            sa_crypto_cipher_context* context,
            sa_cipher_algorithm cipher_algorithm,
            sa_cipher_mode cipher_mode,
            sa_key key) {
        sa_crypto_cipher_init_s cipher_init = {API_VERSION, INVALID_HANDLE, cipher_algorithm, cipher_mode, key};
        sa_status const status = invoke(session, SA_CRYPTO_CIPHER_INIT,
                TEEC_MEMREF_TEMP_INOUT, &cipher_init, sizeof(cipher_init));
        *context = cipher_init.context;
        return status;
    }

    sa_status cipher_process(
            void* session,
            bool last,
            sa_crypto_cipher_context context,
            uint32_t out_buffer_type,
            uint32_t in_buffer_type,
            std::vector<uint8_t>* out,
            std::vector<uint8_t>& in,
            size_t* bytes_to_process = nullptr) {
        // A NULL out is a length query: the TA returns the required output length in bytes_to_process.
        sa_crypto_cipher_process_s process = {API_VERSION, context, in.size(), out_buffer_type, 0, in_buffer_type, 0};
        sa_status const status = invoke(session, last ? SA_CRYPTO_CIPHER_PROCESS_LAST : SA_CRYPTO_CIPHER_PROCESS,
                TEEC_MEMREF_TEMP_INOUT, &process, sizeof(process),
                out != nullptr ? TEEC_MEMREF_TEMP_OUTPUT : TEEC_NONE, out != nullptr ? out->data() : nullptr,
                out != nullptr ? out->size() : 0,
                TEEC_MEMREF_TEMP_INPUT, in.data(), in.size());
        if (bytes_to_process != nullptr)
            *bytes_to_process = process.bytes_to_process;

        return status;
    }

    sa_status cipher_release(
            void* session,
            sa_crypto_cipher_context context) {
        sa_crypto_cipher_release_s release = {API_VERSION, context};
        return invoke(session, SA_CRYPTO_CIPHER_RELEASE, TEEC_MEMREF_TEMP_INPUT, &release, sizeof(release));
    }

    class TaInvokeCipherProcessInvalidBufferTypeTest
        : public ::testing::TestWithParam<std::tuple<bool, bool, bool>> {};

    // A process/process_last call with an out-of-range out or in buffer type must fail without leaking the cipher
    // lock or the cipher/client reference counts: a later release of the cipher and close of the session must
    // complete.
    TEST_P(TaInvokeCipherProcessInvalidBufferTypeTest, releaseAndCloseDoNotHang) {
        bool const last = std::get<0>(GetParam());
        bool const invalid_out = std::get<1>(GetParam());
        bool const release_first = std::get<2>(GetParam());

        child_result const result = run_in_child([last, invalid_out, release_first](int fd) {
            void* session = nullptr;
            if (ta_open_session_handler(&session) != SA_STATUS_OK)
                return 1;

            std::vector<uint8_t> key_bytes(16, 0x11);
            sa_key key;
            if (import_key(session, &key, SA_KEY_FORMAT_SYMMETRIC_BYTES, key_bytes) != SA_STATUS_OK)
                return 2;

            sa_crypto_cipher_context context;
            if (cipher_init(session, &context, SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT, key) !=
                    SA_STATUS_OK)
                return 3;

            step(fd, STEP_CIPHER_READY);
            std::vector<uint8_t> in(16, 0x22);
            std::vector<uint8_t> out(16);
            sa_status const status = cipher_process(session, last, context,
                    invalid_out ? INVALID_BUFFER_TYPE : static_cast<uint32_t>(SA_BUFFER_TYPE_CLEAR),
                    invalid_out ? static_cast<uint32_t>(SA_BUFFER_TYPE_CLEAR) : INVALID_BUFFER_TYPE, &out, in);
            if (status != SA_STATUS_INVALID_PARAMETER)
                return 4;

            step(fd, STEP_PROCESS_REJECTED);
            if (release_first && cipher_release(session, context) != SA_STATUS_OK)
                return 5;

            step(fd, STEP_CLOSING_SESSION);
            ta_close_session_handler(session);
            step(fd, STEP_SESSION_CLOSED);
            return 0;
        });

        EXPECT_FALSE(result.hung) << "TA hung after step " << result.last_step << " ("
                                  << static_cast<int>(STEP_PROCESS_REJECTED) << " = in cipher release, "
                                  << static_cast<int>(STEP_CLOSING_SESSION) << " = in session close)";
        EXPECT_EQ(result.last_step, STEP_SESSION_CLOSED);
        EXPECT_EQ(result.exit_code, 0) << "1-5 = the setup or the call failed in the child";
    }

    INSTANTIATE_TEST_SUITE_P(
            TaInvokeCipherProcessInvalidBufferTypeTests,
            TaInvokeCipherProcessInvalidBufferTypeTest,
            ::testing::Combine(
                    ::testing::Bool(),   // process_last
                    ::testing::Bool(),   // invalid out (else invalid in)
                    ::testing::Bool())); // release the cipher before closing the session

    class TaInvokeCipherProcessLengthQueryTest : public ::testing::TestWithParam<bool> {};

    // A length query (no out buffer) returns the required length for a valid in buffer type and rejects an
    // out-of-range in buffer type.
    TEST_P(TaInvokeCipherProcessLengthQueryTest, failsInvalidInBufferType) {
        bool const last = GetParam();
        void* session = nullptr;
        ASSERT_EQ(ta_open_session_handler(&session), SA_STATUS_OK);
        std::shared_ptr<void> const session_closer(session, ta_close_session_handler);

        std::vector<uint8_t> key_bytes(16, 0x11);
        sa_key key;
        ASSERT_EQ(import_key(session, &key, SA_KEY_FORMAT_SYMMETRIC_BYTES, key_bytes), SA_STATUS_OK);

        sa_crypto_cipher_context context;
        ASSERT_EQ(cipher_init(session, &context, SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT, key),
                SA_STATUS_OK);

        std::vector<uint8_t> in(16, 0x22);
        size_t bytes_to_process = 0;
        EXPECT_EQ(cipher_process(session, last, context, SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR, nullptr, in,
                          &bytes_to_process),
                SA_STATUS_OK);
        // Unpadded AES-ECB has no final output, so process_last reports 0 bytes.
        EXPECT_EQ(bytes_to_process, last ? 0 : in.size());

        EXPECT_EQ(cipher_process(session, last, context, SA_BUFFER_TYPE_CLEAR, INVALID_BUFFER_TYPE, nullptr, in),
                SA_STATUS_INVALID_PARAMETER);

        EXPECT_EQ(cipher_release(session, context), SA_STATUS_OK);
    }

    INSTANTIATE_TEST_SUITE_P(
            TaInvokeCipherProcessLengthQueryTests,
            TaInvokeCipherProcessLengthQueryTest,
            ::testing::Bool()); // process_last
} // namespace
