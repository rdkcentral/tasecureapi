# Module Documentation

# History

|Version|Date (YY-MM-DD) |Comments|Author|
|-------|----------------|------|-----|
|0.1 (Draft)| 22/07/21 | Draft| G. Weatherup|
|0.2 (Draft)|24/02/20221|Updated document | Anjali Thampi |

## Table of Contents

- [Overview](#overview)
- [Structure](#structure)
- [Reference Template](#reference-template)

# Overview

As part of the requirement in creating a code module, it must be documented.

This class creates a common framework for including documentation in a common way.

- Template Location - https://github.com/comcast-sky/rdk-components-hal-doxygen

# Structure

The structure of repo of the surrounding module is expected to be :-

```
.
├── docs
│   ├── build                   -> [This repo]
│   │   ├── pages               -> [Common Markdown files to include]
│   └── template                -> [Reference template][(#reference_template)
│   ├── generate_docs.sh        -> module specific script to call ./build/Makefile [user defined]
│   ├── output                  -> Output Directory [Autogenerated]
│   └── pages                   -> User defined pages *.md search pattern applied from the doxygen configuration
│       ├── CONTRIBUTING.md -> ../../CONTRIBUTING.md    -> Link to page to include from top level .md extension required
│       ├── halspec.md                                  -> First Page in the documentation
│       ├── images                                      -> Contains images to include from the .md files
│       ├── LICENSE.md -> ../../LICENSE                 -> Link to page to include from top level .md extension required
│       └── NOTICE.md -> ../../NOTICE                   -> Link to page to include from top level .md extension required
├── include                                             -> Location of header files *.h search pattern applied from the doxygen configuration
```

* Note: pages *.md is searched, as well as include/*.h

# Reference Template

Including in this repository in the `template` directory reference structure for the document directory.

This should be copied verbatim, then modifier as required for the specific component where `HAL` documentation is to be generated.

```
template
└── docs
    ├── generate_docs.sh
    └── pages
        ├── CONTRIBUTING.md -> ../../CONTRIBUTING.md
        ├── README.md -> ../../README.md
        ├── halSpec.md
        ├── images
        │   ├── sequence1.png
        │   ├── sequence_example.mmd
        │   ├── state1.png
        │   └── state_example.mmd
        ├── LICENSE.md -> ../../LICENSE
        └── NOTICE.md -> ../../NOTICE
```

The `generate_docs.sh` when ran will create this `git repo` under the `build` directory.
