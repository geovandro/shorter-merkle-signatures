# Shorter Merkle Signatures
A reference C implementation of the technique introduced in 2016 at "Shorter hash-based signatures" by G. Pereira, C. Puodzius and P. Barreto to reduce signature footprints of post-quantum Merkle-based digital signatures.


Note: The current implementation is work in progress! Don't use it.

# Compilation instructions

Just type make at the root directory.

The executable files *mss-bench* and *mss-test* will be generated inside *bin* directory.

The file mss-bench benchmarks key generation, signing and signature verification as well. All leaves (WINTERNITZ One Time Signatures) are used to sign and an average time for all leaves is taken.

The file *mss-test* tests the signatures for all the leaves and authentication paths in the merkle tree. It outputs the exact number of leaves failed in case that happens.

You can change the tree height by using the following compilation flag

>  **make MSS_HEIGHT=5**

Notice that treehash algorithm is being used, this the parameter MSS_K should be changed accordingly.
The restrictions on MSS_K are:

1. (MSS_HEIGHT - MSS_K) must be even
2. 2 <= K < MSS_HEIGHT

Thus, for MSS_HEIGHT=5, MSS_K in {3}.

>  **make MSS_HEIGHT=5 MSS_K=3**

Similarly, for MSS_HEIGHT=6, MSS_K in {2,4}.

>  **make MSS_HEIGHT=6 MSS_K=2**

or

>  **make MSS_HEIGHT=6 MSS_K=4**

Increasing MSS_K increases the state size but signing is faster.

Moreover, one can use the WINTERNITZ_W parameter for a signature size x speed tradeoff.
The larger the WINTERNITZ_W the shorter the signature sizes, but keygen and signing are slower.
The library currently provides three options: WINTERNITZ_W in {2,4,8}.
A complete example is given bellow.

>  **make MSS_HEIGHT=10 MSS_K=8 WINTERNITZ_W=2**

Then, try to run

>  **./bin/mss-test**

or

>  **./bin/mss-bench**
