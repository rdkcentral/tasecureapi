# Security API (SecAPI) RFCs

## Table of Contents

+ [RFC Process Considerations](#rfc-process-considerations)
+ [RFC Process](#rfc-process)
+ [RFC Life Cycle](#rfc-life-cycle)
+ [Leaders](#leaders)
+ [Format Conventions](#format-conventions)
+ [Terminology](#terminology)

Many changes, including bug fixes and documentation improvements can be implemented and reviewed via
the normal GitHub pull request workflow.

Some changes though are "substantial", and we ask that these be put through a design process and
produce a consensus among the Comcast TCP (Trusted Computing Products) team.

The "RFC" (Request for Comments) process is intended to provide a consistent and controlled path for
new features to enter the project. The process allows for technical discussion and creating
consensus on new features prior to implementation across different platforms in different languages.

This RFC process is used to make feature and interface proposals to the Security API.

This process is under **active development** and feedback is encouraged on how we can improve on
feature development and collaboration across platforms.

## RFC Process Considerations

You should consider using this process if you intend to make "substantial" changes to the Security
API. What constitutes a "substantial" change is evolving based on community norms and varies
depending on what part of the ecosystem you are proposing to change, but may include the following:

- Any addition, removal, or change to a public API.
- A new feature that creates or changes a public API, and may require a feature flag if introduced.
- The removal of features that already shipped as part of the release channel.

The RFC process can also be helpful to encourage discussions about a proposed feature as it is being
designed, and incorporate important constraints into the design while it's easier to change, before
the design has been fully implemented.

## RFC Process

In short, to get a major feature added to the SecAPI, one usually first gets the RFC merged into the
RFC repo as a markdown file. At that point the RFC is 'active' and may be implemented with the goal
of eventual inclusion into the SecAPI.

* First, search prior proposals and proposals that have been denied in the past before proposing
  something new. These can be found by browsing closed and merged pull requests.
* For those with write access to main repository (**Placeholder for rfc repo here**), create a
  branch to hold your proposed RFC.  For those without write access, create a fork of the main
  repository.
* Copy `0000-template.md` to `accepted/0000-my-feature/README.md` (where 'my-feature' is
  descriptive. don't assign an RFC number yet).
* Fill in the RFC. Put care into the details: **RFCs that do not present convincing motivation,
  demonstrate understanding of the impact of the design, or are disingenuous about the drawbacks or
  alternatives tend to be poorly-received**.
* All images and other supporting artifacts linked directly from the RFC markdown should be placed
  within the RFC-specific directory
* Submit a pull request. As a pull request the RFC will receive design feedback from the larger
  SecAPI user community, and the author should be prepared to revise it in response.
* Build consensus and integrate feedback. RFCs that have broad support are much more likely to make
  progress than those that don't receive any comments.
* RFCs rarely go through this process unchanged, especially as alternatives and drawbacks are shown.
  You can make edits, big and small, to the RFC to clarify or change the design, but make changes as
  new commits to the pull request, and leave a comment on the pull request explaining your changes.
  Specifically, do not squash or rebase commits after they are visible on the pull request.
* Eventually, through considering many factors such as resource constraints and team priorities, the
  team will decide whether the RFC is a candidate for inclusion into the SecAPI.
* At this point, a **Leader**, who is a member of the Comcast TCP team, will be assigned to the RFC
  using the GitHub assignee feature. See below for details on responsibilities of RFC Leaders.
* At the Leaders discretion, the RFC will enter a "final comment period" (FCP) lasting 7 days. The
  beginning of this period will be signaled with a comment and tag on the RFC's pull request.
* An RFC can be modified at the end of the FCP based upon feedback from the team and community.
  Significant modifications may trigger a new final comment period. This should be decided by the
  RFC Leader.
* An RFC may be rejected by the team after public discussion has settled and comments have been made
  summarizing the rationale for rejection. The Leader should then close the RFC's associated pull
  request. A comment is included in the pull request that shows the pull request was rejected.
* An RFC may be accepted at the close of its final comment period. The Leader will merge the RFC's
  associated pull request, at which point the RFC will become 'active'.

## RFC Life Cycle

Once an RFC becomes active, then authors may implement it and submit the feature as a pull request
to the appropriate repo. Becoming 'active' is not a rubber stamp, and in particular still does not
mean the feature will ultimately be implemented and merged; it does mean that the core team has
agreed to it in principle and are amenable to implementing it.

Furthermore, the fact that a given RFC has been accepted and is 'active' implies nothing about what
priority is assigned to its implementation, nor whether anybody is currently working on it.

Modifications to active RFC's can be done in follow up PR's. We strive to write each RFC in a manner
that it will reflect the final design of the feature; but the nature of the process means that we
cannot expect every merged RFC to actually reflect what the end result will be at the time of the
next major release; therefore we try to keep each RFC documented somewhat in sync with the feature
as planned, tracking such changes via follow up pull requests to the document.

## Leaders

There are no restrictions on who can submit proposals to the repo, provided they follow the process
outlined above. For this reason, a "Leader", who is a member of the Comcast TCP team, will be
assigned according to the process above, and is expected to fulfill the following responsibilities:

* Tracking the feedback and keeping the proposal in check with the discussions. This means that the
  Leader often collaborates with the proposal author on the text of the proposal.
* Moves the proposal into the FCP state and makes an announcement to the team.
* Merges or closes the proposal PR as necessary.
* Acts as the point of contact and subject matter expert when development teams move forward with
  implementation.

If an RFC is submitted by a member of the Comcast TCP team, they may assign themselves as the Leader
once it is decided the proposal is a candidate for inclusion. However, this is not required and may
be passed to another volunteer.

A member of the Comcast TCP team may volunteer, or one may be assigned, if a proposal is made by
someone outside of the team.

If desired, this role may be shared by two or more members of the team.

## Format Conventions

RFCs are submitted in markdown format, and follow the following conventions:

* Maximum line length is 100 characters.
* Single space after period before next sentence.
* Blank line between a section header and the header text.

## Terminology

Definitions of commonly used terms in RFCs to avoid any ambiguity and confusion in RFC descriptions.
