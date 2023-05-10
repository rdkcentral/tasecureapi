- Feature Name: Hardening against TOCTOU
- Author(s): Bastien Simondi
- Start Date: 2023-04-07
- RFC PR: 0006
- Leader(s): Eric Berry

## Introduction

Add mechanics to harden the code against Time-of-Check / Time-of-Use (TOCTOU) attacks.

## Motivation / use-cases

TOCTOU is a class of security vulnerabilities that is hard to avoid in complex code bases, and can 
be especially challenging when exchanging data between different execution environments with shared 
memories.
All parameters and fields coming from the outside world (anything calling inside of the `tasecureapi` code) 
should be sanitized, but special concern is to make sure there is no possibilities for the value 
to change between the sanitization and the use of the value. Even a very short window can present 
opportunities and be abused. In general it is preferable to cache (create a copy of) all structures 
and parameters coming from outside of the `tasecureapi` code.
Abuse of TOCTOU attacks can lead to serious security vulnerabilities directly or indirectly 
leading to data compromise or arbitrary data execution in the worst cases.

## Updates/Obsoletes

None

## Affected platforms

All

## Open Source Dependencies

None

## Detailed design

Code can rapidly get complex and even with the best intent and expertize will eventually introduce 
mistakes leading to TOCTOU opportunities.

The recommendation is to systematically copy all data coming from the outside world with the 
exception of video or audio payloads. 
Rules could be created to reserve some of the RPC Global Platform (GP) parameters for 
parameters/values, and some for payloads, so that some buffers are always copied/cache internally 
(e.g. params[] 0 and 1), and some could be used directly even if shared but will never be involved 
in code logic decisions (e.g. params[] 2 and 3). Apply this consistent protocol for all of the 
commands that can be dispatched, at the dispatcher level.

Note that, particular attention should be made to protect nested pointers. While the use of nested pointers is discouraged, if 
there are such practices, then the nested pointers should obey the same rules and the pointed 
structure shall be cached as well.

## Drawbacks

None

## Alternatives considered

None

## Unresolved questions

None

## Future possibilities

None

## References

[TOCTOU Issue](https://cwe.mitre.org/data/definitions/367.html).
