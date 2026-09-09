This branch is for prng uses specifically.  This version will fail the test vectors because it
uses a 64 bit counter and a 64 bit nonce, whereas the test vector in the main branch uses
a 32 bit counter and a 96 bit nonce.
