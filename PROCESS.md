# TaSecureApi Work Process

This document describes the branching and work process adopted by the TaSecureApi project.

## Branching

The TaSecureApi GitHub repository managed in RDK Central will employ a fork workflow development
process consisting of the following branches:

- `main`: Release/production ready version of source code and specifications.
- `Issue_XX`: Custom branch used for development of a particular feature. An Issue is created in GitHub identifying
the feature and a branch will be created for working on this feature. The branch is checked into a developer's
fork of this repository and a Pull Request is created into the main branch of this repository.

## Work Flow

Users will make contributions to either a feature or the main branch. Submissions will undergo the
following process stages before being merged into the branch:

- GitHub code review
- Build verification
- Compliance scan
- Unit test validation

Reference
https://wiki.rdkcentral.com/display/CMF/Gerrit+Development+Workflow
