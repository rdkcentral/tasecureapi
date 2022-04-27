# TaSecureApi Release Process

This document describes the process to release source code and specifications associated with the
TaSecureApi project.

## (1) Tag the repository

### Tagging via Gerrit

From within a local copy of the repository with HEAD at the desired commit to be tagged and
released, use git to create an annotated tag and complete via a typical gerrit code review.

```sh
$ git tag -a <tag name> -m "<tag message>"
$ git push <remote> -tags
```

### Tagging Directly

RDK Central gerrit repository owners have the ability to directly push annotated tags without going
through a gerrit code review.

### Naming Conventions

For consistency, release commits should be tagged using the following syntax:

```text
`<ReleaseName>-<ReleaseVersion>`
```

where:
- `<ReleaseName>` is the name of the code or specifications being tagged. Tag name shall be
  specified using `UpperCamelCase` syntax.
- `<ReleaseVersion>` is the string representing the version being released. The set of characters
  allowed for the version string is restricted to alphanumeric characters and the period symbol. For
  example, `1.4.DO3`.

### Additional References

Informative git tagging tutorial is available [here](https://git-scm.com/book/en/v2/Git-Basics-Tagging).

## (2) Generating Release Documentation

Documents and specifications should be rendered into a common document viewing format such as HTML
and PDF. To ensure consistent generation, the use of the [Atom](https://atom.io) text editor is
encouraged.

To generate release documentation using Atom, for each document:
- Open the Markdown document.
- Generate Markdown preview (`Ctrl+Shift+M`).
- Save the preview as HTML.
- Open the saved HTML document in a browser.
- Print the opened HTML document in the browser as PDF.


