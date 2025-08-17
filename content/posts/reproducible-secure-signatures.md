---
date: '2025-08-17T16:00:43+02:00'
draft: false
title: 'Secure signatures without a private key'
author: [ 'Paul Meyer', 'Leonard Cohnen' ]
tags:
    - confidential computing
    - security
    - AMD SEV-SNP
    - reproducible builds
    - cryptography
showtoc: true
---

*Reproducible builds allow anyone to verify that a binary matches its source code.
But what if the build artifact must contain a cryptographic signature?
Reproducing the signature requires the private key, which defeats the purpose of reproducibility.
In this post, we present a technique based on ECDSA public key recovery that produces signatures which are both secure and fully reproducible, without anyone ever knowing a private key.*

## Build artifacts with signatures - a reproducibility issue

Remote attestation is a fundamental part of Confidential Computing.
It can be used to prove what software is running in a remote environment.
Users of such an attested environment do not need to trust the software vendor, provided the code is accessible and can be audited.
A fundamental requirement for this is reproducible builds.
A verifying party needs to be able to audit the source and reproduce the build artifacts bit-by-bit to ensure the audited software is actually running within the systems and covered by remote attestation.
Reproducible builds exclude the software vendor from the trusted computing base[^1].

When signatures are part of a build artifact, reproducible builds get tricky.
One case where we encountered this at Edgeless Systems is the AMD SEV-SNP ID block.
The ID block is a structure provided when launching a guest.
It contains the expected launch measurement, a guest policy, and a signature by the guest owner.
Launch measurement and guest policy are validated during the boot of the confidential guest, and the guest won't start if there is a mismatch.
The signature is checked for validity, and the digest of the public key is included in the attestation report, which can later be validated to match the guest owner's key.

In [Contrast], we ship the ID block as part of our build artifacts, sometimes included in an [IGVM] guest image.
This turned out to be a challenge: how can we enable a verifying party to reproduce the full artifact, bit-by-bit, including the signature over the ID block?
The verifying party would need the private key used during build to reproduce the signature!

First, we thought that the signing of the ID block was a superfluous mechanism, as all parameters are reflected in the attestation report, too.
If a confidential guest were maliciously configured with an altered guest policy or software and the signature mechanism wasn't there, the guest would still be able to start, but the changed parameters would be reflected in the attestation report.
As we perform remote attestation before trusting a system in Contrast, such manipulation would be discovered at that point.
The signature doesn't add any security in this scenario.
So the first thing we did was using a [snakeoil] key for the signature during build, and committing the private key to our repository, so it could be used to reproduce the exact signature.

Revisiting the [SEV-SNP ABI spec], we later found out that the signature is an important security mechanism in SNP guest migration scenarios.
So the issue we were facing was the following: we needed a correct, secure signature for the ID block that anyone can reproduce.
Correct means that verification of the signature with the public key succeeds as long as the signed artifact hasn't changed.
Secure means that nobody, including the artifact creator, can create new (message, signature) pairs that verify correctly under the used public key.

Our first idea for a solution was based on another confidential computing technology: SGX enclaves.
If the ephemeral key generation and signing happened in an SGX enclave, we could generate a quote of how we created that signature in our build process.
That quote would include the public key and prove that the private key never left the enclave.
While the verifying party wouldn't be able to reproduce the signature, they would still be able to audit the process and be assured that no one has access to the private key of the public key used in the ID block.
However, this solution would not only be complex for us to implement, but also significantly increase the complexity of the verification process.
It would also introduce a second hardware vendor as a trusted party.

Unsatisfied with that solution, we came up with something simpler, far more elegant: a cryptographic solution, based on the possibility of recovering the public key from a (message, signature) pair in ECDSA.

[snakeoil]: https://en.wikipedia.org/wiki/Snake_oil_(cryptography)
[IGVM]: https://github.com/microsoft/igvm
[SEV-SNP ABI spec]: https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf
[Contrast]: https://github.com/edgelesssys/contrast

[^1]: In contrast to signed build artifacts, where a user can only ensure the software wasn't manipulated in transit, but the software vendor itself remains a trusted party

## Reminder: ECDSA signatures

This article aims to explain the solution on a cryptographical level.
The following subsections are intended as a quick refresher for those who are familiar with basic cryptography.
For an introduction and more detailed explanation, see [Understanding Cryptography] by Christof Paar et al., which you might be able to find online in full text.
The Elliptic Curve Digital Signature Algorithm (ECDSA) uses elliptic curves over prime fields $\mathbb{Z}_p$.

[Understanding Cryptography]: https://link.springer.com/book/10.1007/978-3-662-69007-9

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
4. Let $r = x_R \mod q$, where $x_R$ is the x-coordinate of $R$.
5. Compute $s = (h(m)+d \cdot r)k_E^{-1} \mod q$.
6. The signature is $(r, s)$.

### Verification

1. Compute $u_1 = h(m) \cdot  s^{-1} \mod q$.
2. Compute $u_2 = r \cdot  s^{-1} \mod q$.
3. Compute $P = u_1A + u_2B$.
4. If $x_P \equiv r \mod q$, the signature is valid.

### Security

ECDSA is EUF-CMA (Existential Unforgeability under Chosen Message Attack) secure.
This means that an attacker knows the public key and can query an oracle for valid signatures on messages of their choice.
The messages can be chosen adaptively, so the attacker can base future queries on past (message, signature) pairs.
At some point, the attacker stops querying the oracle and tries to produce a valid (message, signature) pair for a message they have not previously queried.
The attacker breaks EUF-CMA security if the verification under the given public key succeeds.
For more information, see [Mathew Green's blog] on this topic.

[Mathew Green's blog]: https://blog.cryptographyengineering.com/euf-cma-and-suf-cma/

## ECDSA public key recovery

ECDSA has a property that might be surprising at first glance: using a message and a signature, it is possible to reconstruct the public key.
This is the cryptographic mechanism we will use to solve the signature issue in our build artifacts.
Let's look at how public key recovery works on a cryptographic level.

Given a message $m$, its signature $(r, s)$, the elliptic curve parameters $(p, a, b, q, A)$, and hash function $h$, it is possible to recover the public key $B$.

1. Choose $x_R$ from $r, r+q, r+2q, \ldots$.[^2]
2. Find $R = (x_R, y_R)$, so that $y_R$ satisfies the curve function and $R$ is on the curve.
3. Compute $u_1 = -h(m) \cdot r^{-1} \mod q$
4. Compute $u_2 = s \cdot r^{-1} \mod q$
5. Compute $B = u_1A + u_2R$ as candidate for public key.

In step 2 there might be multiple points that satisfy the curve function, resulting that we recover only a candidate in step 5.
This can be made deterministic in the implementation by selecting always the point with the smallest $y_R$ in step 2.

The algorithm is described in more detail in [*Standards for Efficient Cryptography (SEC) 1: Elliptic Curve Cryptography*](https://www.secg.org/sec1-v2.pdf), Section 4.1.6, as well as on [Wikipedia], where a proof is also presented.

[Wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery

[^2]: For NIST curves, there are two candidates at most.

## Artifact signature without private key

As described, our goal is to create a signature over an artifact that is both correct and secure as well as reproducible by anyone.

To achieve this, we use the following fixed signature for all artifacts we produce:

$$
(r, s) = (2, 1)
$$

The value of $r$ in the fixed signature must correspond to a valid point on the curve.
Choosing $r = 2$ ($r$ is the x-coordinate) yields a valid point for P-256/P-384, and both $r$ and $s$ are trivially in the required range $[1, q-1]$.
It is important that these are [nothing-up-my-sleeve numbers]: the transparent, trivial constants make it implausible that the signature was deliberately chosen to match a known private key.

Given this fixed signature, we can recover an artifact-specific public key $B$ for each artifact using the ECDSA public key recovery.
The recovered key will verify the fixed signature correctly only for that exact artifact.

We can embed the signature and public key digest in our build artifact. Any critical observer can then verify with the following steps:

1. Rebuild the artifact from source.
2. Recover the public key from the constant signature and the hash of the artifact.
3. Compare the embedded public key digest with the recovered public key digest.

The implementation of this approach for the SEV-SNP ID block in Contrast can be found in [this PR].
Another implementation for ID blocks can be found in the [Mushroom project].

[nothing-up-my-sleeve numbers]: https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
[this PR]: https://github.com/edgelesssys/contrast/pull/1319
[Mushroom project]: https://github.com/Freax13/mushroom/pull/129

### Security considerations

The security of our construct is related to, but not a direct reduction from, standard ECDSA EUF-CMA security, as the public key is derived from a fixed signature rather than sampled by standard key generation.
We do not know the private key $d$ for the recovered public key $B$, and computing it from $B$ is believed infeasible under the elliptic curve discrete logarithm assumption.
To forge a valid signature for a different message (like a malicious, attacker-crafted ID block) under $B$, an attacker would need to either learn the discrete log of $B$ and forge under that key, or find another message that yields the same recovered public key, which amounts to a second-preimage attack on the hash.
Note that ECDSA is not strongly unforgeable: given a valid $(r, s)$, the pair $(r, q-s)$ is also valid for the same message and key.
This is not a concern here, as the verifier compares the recovered public key digest against the expected value, not the signature itself.
The nothing-up-my-sleeve property of $(2, 1)$ ensures that the fixed signature was not deliberately chosen to match a known private key, making intentional trapdoor selection implausible.

## Conclusion

Signatures in build artifacts break reproducibility, as reproducing a signature requires access to the private key.
By using a fixed nothing-up-my-sleeve signature and recovering the public key via ECDSA public key recovery, we can create signatures that are correct, secure, and fully reproducible, without anyone ever knowing a private key.
The security of this approach reduces to the hardness of the elliptic curve discrete logarithm problem and ECDSA's EUF-CMA security.
While we developed this technique for the AMD SEV-SNP ID block in the context of Confidential Computing, it applies to any scenario where a reproducible yet secure ECDSA signature is needed.
