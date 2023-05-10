- Feature Name: Integer Overflow Systematic Checks
- Author(s): Bastien Simondi
- Start Date: 2023-04-07
- RFC PR: 0005
- Leader(s): Eric Berry

## Introduction

Add systematic integer overflow sanitization checks to harden the code logic and mitigate abuses.

## Motivation / use-cases

Integer overflows is a class of security vulnerabilities that is hard to avoid in complex code
bases, and is challenging for static analysers. The arithmetic behind integer overflow is well
documented across the internet. All parameters and fields coming from the outside world (outside world
being any code that calls inside of the TASECUREAPI code) could be of any value and should be
checked against valid ranges, but that alone falls short. All resulting values of an operation
involving one or many fields from the outside world should also be evaluated to be in within
acceptable ranges.

## Updates/Obsoletes

-

## Affected platforms

-

## Open Source Dependencies

-

## Detailed design

Systematically applies to all integer operations that involve, directly or indirectly, any
field/parameter that can be under the influence of the outside world. add (A+B), sub (A-B), and mult
(A*B) operations are in scope. More complex operations shall be decomposed and checks for intermediate
values, e.g. (A+B+C+B) should be decomposed on
- check independently A, B, C and D values
- check for A + B
- check for (A + B) + C
- check for ((A + B) + C) + D
Same applies for any combination of add, sub and/or mult

Integer overflows sanitization checks should also apply to pointers and special care should be taking
that the resulting pointer of an operation is within expected ranges.

There are various ways of checking for integer overflows, which are documented over internet.
Nonetheless I would encourage the code owners to look at builtins macros offered by the compilers.
For instance, GCC offers Builtins, as documented at:
https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
Some OS, like OP-TEE, offer Macros over the compilers builtins, see this is another way of increasing
portability that you can get inspiration from, as it can be seen in
https://github.com/OP-TEE/optee_os/blob/master/lib/libutils/ext/include/util.h

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
