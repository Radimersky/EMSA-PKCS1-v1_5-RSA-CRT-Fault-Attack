EMSA-PKCS1-v1_5 fault attack on RSA-CRT
====================================

Requirements:
pip install pycryptodome

Main.py takes 3 files as command line arguments:
- a public RSA key (in PEM format),
- a message (txt file),
- a signature (binary file - RSA with PKCS #1 v1.5 padding and SHA-512. Padding method described in RFC 8017 (PKCS #1 v2.2) Section 9.2 https://tools.ietf.org/html/rfc8017#section-9.2
hash).

The example input files are:
- public.pem 
- message.txt
- bad_sig.sha512

Example execution:

python ./Main.py public.pem message.txt bad_sig.sha512

The private key information is printed into standart output and a valid signature is in file good_sig.sha512


**How RSA-CRT and fault attack works:**

*RSA-CRT*

The computation of the RSA signature can be sped up using the Chinese
Remainder Theorem (CRT) by computing two partial signatures modulo p
and modulo q and combining them using the CRT into the signature modulo
N.

One such way to do it is to compute the CRT coefficients:

    dp = 1/e (mod p-1) | dp is the modular inverse of e modulo p-1
    dq = 1/e (mod q-1) | dq is the modular inverse of e modulo q-1
    qinv = 1/q (mod p) | qinv is the modular inverse of q modulo p

And then compute and combine the partial signatures:

    s1 = m^dp (mod p) | s1 is the dp-th power of m modulo p
    s2 = m^dq (mod q) | s2 is the dq-th power of m modulo q
    h = (qinv * (s1 - s2)) mod p |
    s = s2 + h * q | s is the resulting signature
    s == m^d (mod N)


**RSA-CRT fault attack*

If an attacker can introduce a fault in the victim's computation of one of
the partial signatures (e.g. a random bit flip in s2, before s1 and s2 are
combined into s), then the computed signature s' will be faulty:

    s2' != m^dq (mod q) | incorrect s2 due to a bit flip
    ...
    s' != m^d (mod N) | results in a faulty signature s'

If the victim does not check the validity of the computed signature s' and
releases the faulty signature, the attacker can compute the factorization of
the modulus N (she obtains a divisor of N, i.e. one of the primes and can
compute the private key):

    s'^e = m (mod p) => s'^e - m = 0 (mod p) => p divides s'^e - m
    s'^e != m (mod q) => s'^e - m != 0 (mod q) => q does not divide s'^e -
m

Hence both p and q divide N, but only p divides s'^e - m, therefore the value
of the private prime p can be computed as the greatest common divisor of
N and s'^e - m (where N is the modulus, s' is the faulty signature,
s'^e is the e-th power of s', and m is the correctly padded message).

    p = GCD(((s'^e mod N) - m) mod N, N)

Therefore, when using RSA-CRT it is necessary to check that the signature is
correct, otherwise the private key could be revealed. An incorrect partial
signature could be computed due to a random or a malicious bit flip in the
computation, or even when the RSA private key is damaged in storage (e.g. the
value of dp or dq has a flipped bit).

The attack only works for a deterministic padding scheme, because the attacker
must be able to compute the correctly padded message independently.

When probabilistic padding is used, such as PSS (see e.g. RFC 8017
- PKCS #1 v2.2), the attacker does not know the random values used by the
victim to generate the probabilistic padding, since they cannot be recovered
from the faulty signature, hence she cannot compute the correct message
m.
