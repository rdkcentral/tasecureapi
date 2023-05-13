#!/usr/bin/env bash

# This script will pull the latest version of doxygen and install it locally for use

# Package Assumptions 
# - build-essentials
# - cmake
# - make

# At the time of writing the latest version is 1.9.5

git clone https://github.com/doxygen/doxygen.git
cd doxygen

mkdir build
cd build
cmake -G "Unix Makefiles" ..
make
make install