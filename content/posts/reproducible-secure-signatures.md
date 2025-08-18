---
date: '2025-08-17T16:00:43+02:00'
title: 'Reproducible Secure Signatures'
tags: [ 'cryptography', 'reproducible builds']
summary: |
    How to create a verifiable ECDSA signature without a private key from a reproducible build artifact using ECDSA public key recovery.
---

## The problem

1. we are the ones providing the build artifact, and it includes a signature
1. we want to exclude ourselves from the TCB
1. the signature must be correct and secure. Correct means that verify(signature, message, public key) returns true. Secure means that nobody, including the artifact builder should be able to create new message signature pairs.
1. customers should be able to reproduce the build and verify the artifact, including the signature, without us being able to provide a different artifact signed with the same private key in any way

## Reminder: ECDSA signatures

The Elliptic Curve Digital Signature Algorithm (ECDSA) uses elliptic curves over prime fields $\mathbb{Z}_p$.
The following subsections are intended as quick refresher to those who are familiar with basic cryptography.
For an introduction and more detailed explanation, see [*Understanding Cryptography* by Christof Paar et al.](https://link.springer.com/book/10.1007/978-3-662-69007-9), which you will likely be able to find somewhere online in full text.

### Key generation

1. Given an elliptic curve $E$ defined over a finite field $\mathbb{Z}_p$ with
    - modulus $p$ (a prime number),
    - coefficients $a$ and $b$ (defining the curve as $y^2 = x^3 +ax +b$), and
    - base point $A$ on the curve, that generates a cyclic group of order $q$.
2. Choose a random integer $d$ in the range $[1, q-1]$.
3. Compute $B = dA$.
    - $k_{pub} = (p, a, b, q, A, B)$ is the public key.
    - $k_{priv} = (d)$ is the private key.

This constructs a discrete logarithm problem, where given $B$ and $A$, it is cryptographically hard to find $d$.

### Signing

1. Given a message $m$ and a hash function $h$,
2. Choose a random integer $k_E$ as ephemeral key in the range $[1, q-1]$
3. Compute $R = k_EA$
4. Let $r = x_R$, where $x_R$ is the x-coordinate of $R$.
5. Compute $s = (h(x)+d \cdot r)k_E^{-1} \mod q$.
6. The signature is $(r, s)$.

### Verification

1. Compute $u_1 = h(m) \cdot  s^{-1} \mod q$.
2. Compute $u_2 = r \cdot  s^{-1} \mod q$.
3. Compute $P = u_1A + u_2B$.
4. If $x_P \equiv r \mod q$, the signature is valid.

### Security

ECDSA is EUF-CMA (Existential Unforgeability under Chosen Message Attack) secure. This means that an attacker knows the public key and can query an oracle for valid signatures to messages chosen by the attacker. Note that the messages can be chosen adaptively, so the attacker could base future messages on the responses of past (message, signature) pairs. At some point, the attacker stop querying the oracle and tries to generate a (message, signature) pair where the attacker must not
have queried the oracle with this message. The attacker breaks EUF-CMA security if the verification under given public key succeeds. 
For more information see [Mathew Green's blog](https://blog.cryptographyengineering.com/euf-cma-and-suf-cma/) about this topic.


## ECDSA public key recovery

Given a message $m$, its signature $(r, s)$ and the elliptic curve parameter $(p, a, b, q, A)$ and hash function $h$, it is possible to recover the public key $B$.

1. How to compute X, R?
2. Compute $u_1 = h(m) \cdot r^{-1} \mod q$
3. Compute $u_2 = s \cdot r^{-1} \mod q$
4. Compute $Q = u_1A + u_2R$ as candidate for public key.

The algorithm is described in more detail in [*Standards for Efficient Cryptography (SEC) 1: Elliptic Curve Cryptography*](https://www.secg.org/sec1-v2.pdf), Section 4.1.6.

## Artifact signature without private key

As described in the beginning, we want to exclude ourselves from the TCB, but still provide a verifiable signature of our artifact.
To archive this, we use a fixed signature for all artifacts:

$$
(r, s) = (2, 1)
$$

It is important that these are [nothing-up-my-sleeve numbers](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number), as otherwise an attacker could use them based on an actual known private key.

Given this fixed signature, we can recovery a unique public key $B$ for each artifact that verifies it.
Finding the private key to this public key is equivalent to solving the discrete logarithm problem.

We can use the signature and public key (digest) in our build artifact and any critical observer can do the following steps to verify:

1. Rebuild the artifact from source.
2. Recover the public key from the constant signature and the hash of the artifact.
3. Compare the embedded public key digest with the recovered public key digest.

## Security

### Private key recovery
The attacker for our scheme knows the following parameters:
1. The public key
1. One message signature pair

This is a weaker security model than EUF-CMA, since in EUF-CMA, the attacker can query the signature for the message in 2. Then they have the same information AND further oracle queries available. Therefore, since ECDSA is EUF-CMA secure, the attacker in our scheme also cannot create new message signature pairs.

In practice to break the scheme using a constant signature, the attacker still needs to find a hash collision in $h$ even when they've recovered the private key.

