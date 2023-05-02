- Feature Name: Hardening memory operations
- Author(s): Bastien Simondi
- Start Date: 2023-04-07
- RFC PR: 0007
- Leader(s): Eric Berry

## Introduction

More often than not memory operations are opening serious vulnerabilities. The recommendation is 
to add systematic hardening on memory operations leveraging execution context and memory types.

## Motivation / use-cases

Memory operations, like setting memory to 0s, or copying memory blocks, when abused can lead to 
disastrous vulnerabilies that are the cornerstones of exploits.
It is crucial for a piece of code to control the memory operations, so they have deterministicly 
safe outcomes. Memory operations come in flavors, some are very explicit via calls to functions 
like memset(), memcpy() or direct assignment like variable X = Y; at times, it can be more 
subtle and delegated to the compiler, like structure assignments.

Either way, at all times the source, destination involved in the memory operation, as well as the 
number of bytes, should all be sanitized and of acceptable values. For each operation, it should 
be straight to answer a few questions like
- what is the memory type of the source, is it a secure memory, is it a shared memory accessible 
to a less secure execution environement?
- what is the size of the memory operation, does it go beyond the allocated memory for the source 
and / or the destination?
- is the transaction from a given memory type to another given memory type allowed? e.g. should 
stack memory be copied over to shared memory?

Systematic memory transaction checks are not always easy, but they do allow to add a significant 
layer of security at the very last moment of processing, and adds value on top of any prior 
sanitization: for example may an adversary manage to abuse an integer overflow and/or manipulate 
one of the source, destination or size parameter, a systematic sanitization at the time of running 
the memory operation provides an extra opportunity to mitigate the abuse.

## Updates/Obsoletes

-

## Affected platforms

-

## Open Source Dependencies

-

## Detailed design

Ideally, all memory transactions would be covered. The systematic approach in inserting those 
checks can rapidly grow into a methodology that is easy to replicate as new code is added. Special 
focus shall be made in layers that are close to the entry point, but subtle weaknesses can cross 
many layers and effort should be done to track and sanitize memory transactions all the way down. 

Memory types depend on the system, the platform, there is no standard memory ranges that are 
either secure or unsecure. It can't be solved without the help of an info from the system the code 
is executed on. The top level idea here is to implement similar logic as the Linux kernel does 
when copying memory back and forth with userland -- with functions, ala copy_from_user(), 
copy_to_user().

The recommendation is to define an interface that aims at providing the memory type to of a given 
memory block.
For instance 'get_memory_type(address, size)' could return an enum from a list like {Shared, 
SecureDataPath, SecureStack, SecureHeap, Invalid} and so forth.
This would be a porting interface that would be asked for integrator partners to implement. 
Note that, this routine shall check that all of the bytes from 'address', over 'size' bytes are 
all inside of a given memory type (in other words, crossing memory types shall return an invalid 
result)

Then depending on the intend of a given memory operation, routines could add allowed memory 
transaction sanitization.
For instance 'cache_from_ree_to_tee(source, destination, size)' would verify that the buffer 
starting at 'source' over 'size' bytes is entirely inside of a memory type 'Shared', as it is 
meant to be REE accessible, and would verify that the buffer starting at 'destination' over 'size' 
bytes is entirely inside of a memory type 'SecureHeap'.
Other routines can easily be defined like 'ree_to_svp()' or 'svp_to_svp()' or 'tee_to_ree()' and 
used where appropriate.

Leveraging systematic checks + this new interface, the code of TASECUREAPI can evolve 
independently from any systems it relies on, and implement secure memory transaction, for as long 
as the relatively simple 'get_memory_type()' is implemented by all partners and reviewed by the 
TASECUREAPI owners.

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
