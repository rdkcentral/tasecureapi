# TaSecureApi Work Process

This document describes the branching and work process adopted by the TaSecureApi project.

## Branching

The TaSecureApi gerrit repository managed in RDK Central will employ a feature branching development
process consisting of the following branches:

- `main`: Release/production ready version of source code and specifications.
- `<feature-name>_feature`: Custom branch used for large or long term development. Source code and
  specifications in these branches may be incomplete or not yet approved for release and general
  use. When development and review process complete, the updates in a feature branch are merged into
  the `main` branch.

### Deprecated and Unused Branches

- `rdk-next`: Community development branch for RDK Central gerrit repositories. Intended as an
  intermediate repository for downstreaming changes into a corresponding Comcast RDK gerrit
  repository. Applicable Comcast `stable2` branch updates are pushed to `rdk-next`.
- `<rdk-dev-yymm>`: RDK Central monthly integration branches baselined off of the `rdk-next` branch.
  These are read only branches intended to offer RDK community members a quicker means of adopting
  updates rather than wait for propagation through Comcast RDK `stable2` branch. RDK Central changes
  destined for the Comcast RDK are taken from this branch and incorporated into a Comcast sprint
  branch for eventual release via `stable2`.

## Work Flow

Users will make contributions to either a feature or the master branch. Submissions will undergo the
following process stages before being merged into the branch:

- Gerrit code review
- Build verification
- Compliance scan
- Unit test validation

Reference
https://wiki.rdkcentral.com/display/CMF/Gerrit+Development+Workflow
