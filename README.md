# WinMallocTracer

* Proof of concept code, tested in a small number of situations.
* This `Pintool` allows you to log and track calls to `RtlAllocateHeap`, `RtlReAllocateHeap`, `RtlFreeHeap`, `VirtualAllocEx`, and `VirtualFreeEx`.
* Currently warns about potential `invalid allocations`, `double frees`, and `memory leaks`.

For more information read: [http://deniable.org/reversing/binary-instrumentation](http://deniable.org/reversing/binary-instrumentation).

