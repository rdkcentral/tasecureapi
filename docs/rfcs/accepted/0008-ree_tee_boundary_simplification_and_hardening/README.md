- Feature Name: REE/TEE boundary simplification and hardening
- Author(s): Bastien Simondi
- Start Date: 2023-04-07
- RFC PR: 0008
- Leader(s): Eric Berry

## Introduction

Crossing trust boundaries create opportunities for adversarial code running in less trusted 
environment, to attack the more trusted environment. Integrating a 3rd party code on the more 
trusted world, is error prone and innevitably creates security loopholes proportionally linear 
with the complexity of the integration. Special attention should be made to move the complexity 
burden out of the partners' hands, and take control of systematic sanitization of the parameters 
at the REE/TEE boundary.

## Motivation / use-cases

In the context of this piece of code, it is assumed that TASECUREAPI is running inside of a 
Trusted Application (TA), executing in a Trusted Execution Environment (TEE), and that a client 
code running in the (less trustworthy) Rich Execution Environment (REE, also known as Application 
CPU) runs Remote Procedure Calls (RPC) towards it, for a variety of exposed APIs.

All of those APIs compose an attack surface for the REE to try to abuse the code running in the 
TA, to compromise secrets, gain execution etc. Every single parameter of all of the exposed APIs, 
shall be consider under an attacker control, and properly sanitized.

Implementing a systematic sanitization layer for all APIs exposed by TASECUREAPI allows to isolate 
and seal the inner code logic against partners integration shortcomings or mistakes that would not 
properly mitigate external abuses. In other words, it moves a large chunk of the assumptions on 
how secure is the integration toward deterministic sanitization checks handled in the inner code 
logic (largely independent from the integration).

This becomes particularly relevant as the number of partners integrating the code grow. Reducing 
the complexity on partners hands, also reduce the complexity of the code review when verifying 
their integration.


## Updates/Obsoletes

-

## Affected platforms

-

## Open Source Dependencies

-

## Detailed design

All parameters getting in the SEC API lib can be tricked and have malicious values. Said 
differently, every single parameter or value that is used directly or indirectly inside of the 
code, shall be sanitized before being used. For all APIs. No exceptions.

Most partners are using Global Platforms (GP) for RPC calls. Special effort should be made to 
offer a compatible or easy to wire interface.
Direct use of GP APIs (or providing an optional glue for GP) would allow the inner code also to 
leverage GP types and take control over the expected types of parameters that are received, this 
will be one less thing for partners to handle.

Special attention in design shall be made to favor partners integration simplicity. Use of GP 
types and API is one option, reducing partners integration code to the minimum with simple 
portability interfaces is another way of enabling that. All efforts in reducing complexity from 
partners' hands have a benefit on the security posture that scale accross integrations.

## Drawbacks

-

## Alternatives considered

-
## Unresolved questions

-

## Future possibilities

-

## References

-
