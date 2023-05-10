- Feature Name: Isolate integrator modifications via porting interfaces
- Author(s): Bastien Simondi
- Start Date: 2023-04-04
- RFC PR: 0004
- Leader(s): Eric Berry

## Introduction

Improve isolation of integration modifications using porting interfaces, to reduce integrators 
complexity, easing adoption and updates.

## Motivation / use-cases

By isolating the core code complexity that is owned by the TASECUREAPI team, and exposing 
modification only via porting interfaces it makes it very explicit what partners are asked to 
modify. In addition to reducing the complexity of integration for partners for the first 
iteration, it also allows to seemlessly update the core functionality with little to no change 
from partners, increasing the chances of update adoption.
Finally, having a clean separation of ownership of the inner code, versus what is asked to 
partners to implement, makes the code review process much easier: no delta should be seen on the 
code, except on the interfaces that are required, which are the only piece of code that now need 
to be reviewed.

## Updates/Obsoletes

None

## Affected platforms

All

## Open Source Dependencies

None

## Detailed design

All places with TODOs in the code should be evaluated and replaced with code logic that is owned 
by TASECUREAPI, and only calling into interfaces that shall be provided by integrators.
example, adding a 'get_uuid()' interface and using it inside of 'transport_autenticate_caller()'

## Drawbacks

None

## Alternatives considered

None

## Unresolved questions

None

## Future possibilities

Any new feature or dependency on the system / HW of a product shall consider adding an interface.

## References

None
