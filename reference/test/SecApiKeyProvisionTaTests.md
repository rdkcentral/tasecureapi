# SecAPI Key Provision File Based TA Tests

## Test Function: fromFileBased

Once you've enabled FILE_BASED_FETCH_KEY, a test function named fromFileBased becomes available.
This function retrieves the key provision data from the specified location (either based on
environment variables or from the /keys directory). It then uses this data to run the specific
tests designed for key provision files.


This document explains how to run tests that rely on key provision files. There are two approaches:

## Using System Variables:

Set Environment Variables: Before running the tests, export specific system environment variables.
These variables likely define paths or locations for the key provision files.

Enable Flag in sa_key_import_common.h: Edit the sa_key_import_common.h header file and turn on 
FILE_BASED_FETCH_KEY flag. This flag instructs the test function to look for key provision files
based on the environment variables.

examlpes on how to set environment variables :
1. Netflix HMAC, wrapping key and ESN number
``` export  netflix_hmac_key=~/PATH/tasecureapi/reference/test/netflix_hmac_key.key ```
``` export  netflix_wrapping_key=~/PATH/tasecureapi/reference/test/netflix_wrapping_key.key ```
``` export  netflix_esn=~/PATH/tasecureapi/reference/test/netflix_esn.bin ```

2. PlayReady private key, certification
``` export  playready_privatekey=~/PATH/tasecureapi/reference/test/playready_private_key.key ```
``` export  playready_cert=~/PATH/tasecureapi/reference/test/playready_cert.bin ```

3. Widevine OEM private key and certification
``` export  widevine_oem_privatekey=~/PATH/tasecureapi/reference/test/widevine_oem_private.key ```
``` export  widevine_oem_cert=~/PATH/tasecureapi/reference/test/widevine_oem_cert.bin ```

## Placing Files in /keys Directory:

Move Key Provision Files: Copy the key provision files you want to use for testing to the /keys
directory in your project or system.

Enable Flag in sa_key_import_common.h: Similar to method 1, edit the sa_key_import_common.h header
file and turn on the FILE_BASED_FETCH_KEY flag. This enables the test fucntion to locate the key
provision files from the /keys directory.



