# Shorter Merkle Signatures
A reference implementation of the technique introduced in 2016 at "Shorter hash-based signatures" by G. Pereira, C. Puodzius and P. Barreto to reduce signature footprints of post-quantum Merkle-based digital signatures.


Note*: The current implementation is work in progress! Don't use it.

# Compilation instructions

Just type make at the root directory

The executable files *mss-bench* and *mss-test* will be generated inside *bin* directory.

The file mss-bench benchmarks key generation, signing and signature verification as well. All leaves (WINTERNITZ One Time Signatures) are used to sign and an average time for all leaves is taken.

The file mss-test tests the signatures for all the leaves and authentication paths in the merkle tree. It outputs the exact number of leaves failed in case that happens.
