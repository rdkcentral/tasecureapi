
MAKE_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_PATH = $(shell dirname ${PWD})/../

export PROJECT_NAME = $(shell basename $(PROJECT_PATH))
export PROJECT_VERSION = "NOT SET"

DOXYGEN_CMD = doxygen

ifeq (, $(shell which $(DOXYGEN_CMD)))
$(error "Doxygen is not found in the PATH:$(PATH), install it with ./doxygen_install.sh")
endif

DOXYGEN_VERSION = $(shell $(DOXYGEN_CMD) -v | tr [:space:] '\n' | head -n1)

ifeq ("", DOXYGEN_VERSION)
$(error "Doxygen is not found in the PATH:$(PATH), install it with ./doxygen_install.sh")
endif

$(info $(echo -e doxygen version: \033[92m$(DOXYGEN_VERSION)\033[0m))

FILES = $(shell find ../../ -name "*.h") 
FILES += $(shell find ./pages -name "*.md")
FILES += $(shell find ../pages -name "*.md")
DEPS = Doxyfile.cfg DoxygenLayout.xml $(FILES)

all: $(DEPS)
	$(DOXYGEN_CMD) Doxyfile.cfg

vars:
	@echo PROJECT_NAME: $(PROJECT_NAME)
	@echo PROJECT_VERSION: $(PROJECT_VERSION)
	@echo PROJECT_PATH:$(PROJECT_PATH)
	@echo MAKE_PATH:$(MAKE_PATH)
	@echo DEPS:$(DEPS)

clean:
	@echo Cleaning output
	@rm -fr $(MAKE_PATH)/../output
	@mkdir -p $(MAKE_PATH)/../output
