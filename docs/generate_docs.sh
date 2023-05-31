#!/usr/bin/env bash

# In the future this should moved to a fixed verison
HAL_GENERATOR_VERSION=main

# This will look up the last tag in the git repo, depending on the project this may require modification
PROJECT_VERSION=$(git describe --tags | sort | head -n1)

# Check if the common document configuration is present, if not clone it
if [ -d "./build" ]; then
    make -C ./build PROJECT_NAME="SecApi (tasecureapi)" PROJECT_VERSION=${PROJECT_VERSION}
    mkdir -p output/html/docs/diagrams
    cp ./diagrams/*.png output/html/docs/diagrams
    cp rfcs/accepted/0002-consolidate_svp_and_non_svp_cipher_apis/SecApi3-Plan.png output/html
else
    echo "Cloning Common documentation generation"
    git clone git@comcast_github:comcast-sky/rdk-components-hal-doxygen.git build
    cd ./build
    git flow init -d
    git checkout ${HAL_GENERATOR_VERSION}
    cd ..
    ./${0}
fi
