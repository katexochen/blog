---
date: '2026-09-22T16:09:59+02:00'
draft: false
title: 'Understanding NvPCRs in systemd v262'
tags:
    - security
    - systemd
    - measured-boot
    - remote attestation
    - platform security
ShowToc: true
---

*systemd answers TPM PCR scarcity with additional PCR-like registers allocated in the TPM's NV memory,
with an anchoring design that was reworked in v262.
In this hands-on deep dive, we rebuild a systemd NvPCR from scratch against a software TPM,
picking up the required TPM concepts along the way, and analyze why the design is secure.*

## Why can't systemd get enough of those PCRs?

<!-- what does systemd need PCRs for -->
Many of systemd's security features rely on TPM PCR measurements: Passwordless full
disk encryption can unlock disks automatically if the PCR measurements are as expected,
preventing credential theft while still allowing unattended reboots of remote machines
with encrypted root disk. Service credentials can be encrypted against the expected
PCR state. Boot-phase bound credentials are also supported, allowing secrets that can only ever
be decrypted in the initrd. And with remote attestation, a machine can prove to another party
what it booted and what happened since, by having the TPM sign its current PCR state (a
so-called quote). All of this is built on PCR measurements.

<!-- what TPM PCRs exist and how are they used -->
TPM PCRs are scarce. On common standard-compliant TPMs there are only 24 PCRs available.
The lower PCR indices 0-7 are owned by the firmware and used for UEFI boot measurements.
16 is a debug PCR that can be reset and is therefore unusable, 17-22 are reserved for
Dynamic Root of Trust for Measurements[^1], and 23 is reserved for application support.
So only 8-15 are left for systemd to do all OS-related measurements[^2].

<!-- why does stuff needs its own PCR -->
From a remote attestation perspective, a single measurement register can be enough to verify
a system. We can use the measurement log to replay the events and interpret what was measured
to land on the final value we observe. But PCRs are not only read by remote verifiers, they
are also what local secrets are locked against, and that use needs predictable values: every
event flowing into such a PCR must be known in advance, otherwise the policy breaks. Some
measurements are inherently unpredictable, depending for example on the closed source vendor
firmware of the individual platform, or on the behavior of users. We might want to include
a login event in our remote attestation quote, but the root disk should still be able to
unlock itself after someone logged in. So the noisy and unpredictable event types need
registers of their own: out of the way of the PCRs that locks depend on, but still measured
and attestable. And that's where systemd was quickly hitting a hard limit: with only eight
PCR slots available to the OS, there isn't much space to give event types their own register.

<!-- how are NvPCRs used in systemd today -->
This is why systemd [introduced NvPCRs in v259]: additional PCR-like registers, allocated in the
TPM's non-volatile memory, hence the name. They host the event types we don't want in the real
PCRs, and their values are consumed through remote attestation. In v262, the
[anchoring of NvPCRs was reworked] to increase their security. Previously, the anchoring was
based on a random secret sealed against PCR 11 and stored on disk, which an attacker could
recover by booting a different OS that replays the expected PCR 11 values, or simply replace
with a secret they know. This blog post describes the reworked design that ships in v262: how it works, and
why it is secure.

[^1]: Dynamic Root of Trust for Measurements is a mechanism to establish a new, verifiable
      chain of trust at runtime, usually supported by the platform through something like
      Intel TXT or AMD SVM.
[^2]: The [UAPI.7] spec documents how firmware and OS PCRs are commonly used.

[UAPI.7]: https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/
[introduced NvPCRs in v259]: https://github.com/systemd/systemd/pull/39463
[anchoring of NvPCRs was reworked]: https://github.com/systemd/systemd/pull/42796

## Setup for follow-along

We'll check out the basic working principles and get a feeling for the matter by
constructing our own NvPCRs against a software TPM on the command line. If you'd
rather just read, that's fine, too, I'll provide all important output.

As a prerequisite, install the required tools, for example with nix or dnf:

```shell
nix shell nixpkgs#{tpm2-tools,xxd,swtpm,openssl}
```
```shell
dnf install tpm2-tools vim-common swtpm openssl
```

Create a directory you want to work in and start the software TPM:

```shell
mkdir state
swtpm socket \
  --tpm2 \
  --tpmstate "dir=$PWD/state" \
  --ctrl "type=tcp,port=2322" \
  --server "type=tcp,port=2321" \
  --flags startup-clear \
  --pid "file=$PWD/swtpm.pid" \
  -d
```

Export the connection details so tpm2-tools knows where to find the TPM:

```shell
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
```

Check the TPM is working by reading the PCRs:

```shell
tpm2_pcrread sha256
```

This should show the PCRs 0-16 being all zero. If not, you might be talking to the TPM of your
platform and not the software TPM, check again that you exported `TPM2TOOLS_TCTI` correctly.
This is important, as we don't want the following experiments to mess with the sealed
secrets of your platform.

## TPM NV index as PCR replacement

<!-- what is an nv index -->
A TPM NV index[^3] is a non-volatile storage slot identified by a unique name. NV indices
persist across reboots and can hold user defined data: an opaque value, a counter, bitfield
or similar. The properties of an NV index define how it behaves and what it can be used for:
its handle, the size of the stored data, a set of attributes controlling how the index can be
manipulated or read, and an authorization policy and authorization value (the latter being the
only non-public property) that optionally specify under which conditions the index can be
manipulated. Each index has a *nameAlg*, the hash algorithm used to compute the unique name
from the public properties of the index[^4] as

`Name = nameAlg || H_nameAlg(marshal(TPMS_NV_PUBLIC))`.

<!-- how to define a nv index -->
Let's create a PCR-like NV index! We are using tpm2_nvdefine from tpm2-tools for this.
`0x01000000` is the handle for the index that we are defining (somewhat randomly picked).
The `--hierarchy=o` flag selects the authorization we define the index under: NV indexes
like ours live in the TPM's owner hierarchy, and defining or undefining them requires the
owner authorization value[^5]. On a typical Linux system that value is empty, so effectively
anyone with access to the TPM device, usually root, holds owner authorization.
The `hash-algorithm` flag corresponds to the previously named nameAlg and is chosen as sha256.
Then we select the attributes for our NV index: `authread|authwrite`, in combination with an
empty authorization value, allows anyone with access to the device to read and write the
index. And `nt=extend` says we want this to be extendable like a PCR.

```shell
tpm2_nvdefine 0x01000000 \
  --hierarchy=o \
  --hash-algorithm=sha256 \
  --attributes="nt=extend|authread|authwrite"
```

Take a look at the result using the following command:

```shell
tpm2_nvreadpublic
```
```
0x1000000:
  name: 000be9606b61ec27bc8deec096dd38a6f8961cb8b3ef2fe879b27de704ab2f3d44e3
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: authwrite|nt=0x1|authread
    value: 0x40044
  size: 32
```

We can see the properties we configured[^6], the size, and the name that is a hash over
the public properties. As you defined the exact same properties as I did, you will get
exactly the same hash as index name.

Now we can use our NV index like a proper PCR and extend it with a measurement, for
example with a login event of user Alice:

```shell
printf 'user-alice-logged-in' > m1.bin
tpm2_nvextend 0x01000000 --input=m1.bin
```

Then read its value:

```shell
tpm2_nvread 0x01000000 --size=32 | xxd -p -c 64
```
```
bd9927a653c6c33297b7d884a8ad99df0f5b5b1c1e1e86f762b3aced8bc77f50
```

<!-- explain the written attribute -->
If we now inspect the NV index again, we can observe something interesting:
The index got a new attribute `written`, indicating that the index has been written
one or more times. As the set of attributes was updated, and the name of the index
is a hash including the attributes, it got a new name too! We will make use of this
later.

```shell
tpm2_nvreadpublic
```
```
0x1000000:
  name: 000b1191942a636c11a57571f0d435c290a1955788229305ce0aa8a2f393e9ed770c
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: authwrite|nt=0x1|authread|written
    value: 0x20040044
  size: 32
```

You can do another measurement if you like, measuring the login event of Bob:

```shell
printf 'user-bob-logged-in' > m2.bin
tpm2_nvextend 0x01000000 --input=m2.bin
tpm2_nvread 0x01000000 --size=32 | xxd -p -c 64
```
```
e758d6e2e54620fd45b9cd1fd57cbba62757f12751d549fd2fc957ed1908ed29
```

At this point, the value of the NV index is `HASH(HASH(0x0 || m1) || m2)`[^7].
The index name didn't change again with the second measurement.

<!-- what is the downside: we can just undefine and redefine -->
So we have an NV index that is extendable in the same way a PCR is. Can we
already use it as PCR replacement? We can't. We are missing a fundamental
property of the real PCRs: To use the measurement chain as proof for anything,
it must not be resettable or replayable during the runtime of the system!
Otherwise an attacker that gained access to the system could just reset the
measurement history and replay the history of an unmanipulated system, making
the attack undiscoverable through remote attestation.

Sadly, this isn't a property the TPM grants us for our PCR-like NV index: We defined the index
at system runtime, and we can undefine it again:

```shell
tpm2_nvundefine 0x01000000 --hierarchy=o
tpm2_nvreadpublic
```

Given the two example measurements we did in this section, if Alice has malicious intentions
and gains root access, and with it owner authorization, they can just undefine and redefine
the index, then replay a history where Alice never logged in. The redefined index gets the
exact same name, and we couldn't notice.

What we need is an index that anyone can extend, but that nobody can restart during the
runtime of the system. Policies are the TPM's tool to express such conditions.

[^3]: See Section "34.2 NV Indices" in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture]
[^4]: Section "13 Names" in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture]
      lists the name equations for all entity types (Table 9), and explicitly describes how the
      name of an NV index changes when the `written` attribute is set.
[^5]: Hierarchies and their authorizations are introduced in Section "10 TPM Control Domains"
      in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture] in case you want to
      dive into it, but not super important for what we are doing here.
[^6]: Notice the `nt=0x1` in the output is a bug in tpm2-tools. `TPM_NT_EXTEND` is 0x4 according
      to spec, and the raw value correctly contains that. I've opened an [upstream PR to fix this].
[^7]: Notice that the `TPM2_NV_Extend` call used by tpm2_nvextend uses the arbitrary bytes provided
      directly in the hash function without pre-hashing: `NV := H_nameAlg(NV_old ‖ input)`.
      `TPM2_PCR_Extend` on the other hand requires a fixed size digest to be passed
      (`PCR := H(PCR ‖ digest_in)`), and `TPM2_PCR_Event` does hashing of the handed event
      itself (`PCR := H(PCR ‖ H(event))`).

[TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf
[upstream PR to fix this]: https://github.com/tpm2-software/tpm2-tools/pull/3600

## Exploring policies

A very powerful concept the TPM interface provides is the policy[^8].
Such a policy is an opaque digest stored with the object it protects, in the `authPolicy`
property we already saw in the public properties of our NV index.
To fulfill a policy, we request a policy session from the TPM. Each session has its own
context, containing a digest called `policyDigest` and a set of constraints that can be
modified by executing policy assertions. A fresh session has a `policyDigest` that is all zero.
Within a session, we can then run different policy commands against the TPM, each
asserting some condition. Some assertions are checked immediately while the command
executes. Others are deferred: the command records a constraint in the session context,
and the TPM only checks it once the session is used for authorization. Either way, each
command extends the session's digest, using the following logic:

`policyDigest := H(policyDigest_old || commandCode || command-specific args)`

That extend scheme works exactly like a PCR, even though the `policyDigest` is not backed by a real PCR.
A caller can present different types of evidence, each extending the `policyDigest`.
If the assertions add up so that the session's `policyDigest` matches the `authPolicy`
of the index, the session is authorized and the desired command can be called with it.
The author of a policy computes the expected `authPolicy` digest via a trial session
in a trusted environment or through pre-calculation offline. A trial session runs the
same digest calculation, but doesn't verify any of the conditions, and in exchange can't
be used to authorize anything. This is what allows an author to compute a policy for a
state the machine currently isn't in.

### `PolicyPCR`

The cool thing is that policies can make permission depend on the machine state by
locking against the expected value of a PCR. Let's create such a policy!
First, we start a trial session to define the policy we want to set on our NV index.
This is done by invoking `tpm2_startauthsession` without the `--policy-session` flag.

```shell
tpm2_startauthsession --session=trial.ctx
```

We then call `tpm2_policypcr` to create an assertion over the currently observed
PCR value(s) we select via `--pcr-list=`. For our experiment, we use PCR 15, one of
the OS-owned PCRs. The application PCR 23 might look like the natural playground, but
like the debug PCR 16 it can be reset at runtime, which is exactly the property we are
trying to get rid of:

```shell
tpm2_policypcr --session=trial.ctx \
  --pcr-list=sha256:15 \
  --policy=pcr15.policy
```
```
7e247a603cd1052cabc095741b8ee2f7458aabeee960b8ec97d7f090171a039a
```

The resulting policy digest is printed and written to `pcr15.policy`[^9].
Then end the session:

```shell
tpm2_flushcontext trial.ctx
```

Let's recreate the NV index from before, this time we protect write access
to it with the policy we just created:

```shell
tpm2_nvdefine 0x01000000 \
  --hierarchy=o \
  --hash-algorithm=sha256 \
  --attributes="nt=extend|authread|policywrite" \
  --policy=pcr15.policy
```

Notice we added both the `--policy=` flag and the `policyWrite` attribute.
We leave the `authRead` untouched. There is a `policyRead` too, but usually
restricting who can extend the index is much more interesting.

```shell
tpm2_nvreadpublic
```
```
0x1000000:
  name: 000b14a6915e5830ff2b83ebc87cdf5ac481fb29637c246489bdab1bba19948bb729
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: policywrite|nt=0x1|authread
    value: 0x40048
  size: 32
  authorization policy: 7E247A603CD1052CABC095741B8EE2F7458AABEEE960B8EC97D7F090171A039A
```

Just trying to extend as before will now fail with an authorization error:

```shell
tpm2_nvextend 0x01000000 --input=m1.bin
```
```
ERROR: Esys_NV_Extend(0x12F) - tpm:error(2.0): authValue or authPolicy is not
available for selected entity
```

Instead, to write to the index, we need to start a policy session and satisfy the policy by
presenting the current PCR 15 state[^10]. After that, we can do the extension, presenting the session
as authorization. And remember to flush the session context at the end.

```shell
tpm2_startauthsession --session=s.ctx --policy-session
tpm2_policypcr --session=s.ctx --pcr-list=sha256:15
tpm2_nvextend 0x01000000 \
  --hierarchy=0x01000000 \
  --auth=session:s.ctx \
  --input=m1.bin
tpm2_flushcontext s.ctx
```

If PCR 15 advances, the policy can't be fulfilled anymore. Run the following command to extend the PCR:

```shell
echo something | tpm2_pcrevent 15
```

Now retry the three steps from before that unlocked the session based on the PCR.
The extend will fail with `tpm:session(1):a policy check failed`, as the PCR advanced and
neither its current value (nor any of its future values!) matches the one included in the
policy anymore. The access to the PCR-bound index expired and can't be regained during the
runtime of the machine.

Finally, undefine the index again with:

```shell
tpm2_nvundefine 0x01000000 --hierarchy=o
```

[^8]: Policies are specified in Section "16.7 Enhanced Authorization" in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture],
      which is a surprisingly readable introduction to the topic. Trial sessions are covered
      in Section "16.7.10 Trial Policy".
[^9]: Reproducing the hash with some constants from the spec:

      `H(zeros32 || 0000017f || 00000001000b03008000 || H(pcr15_value))`

      On the terminal:

      ```shell
      pcrdigest=$(head -c 32 /dev/zero | sha256sum | cut -d' ' -f1)
      printf '%064d0000017f00000001000b03008000%s' 0 "$pcrdigest" \
          | xxd -r -p | sha256sum
      ```
[^10]: `PolicyPCR` can be immediate and deferred at the same time, depending on its
      parameters: the caller may pass the PCR digest they expect, which the TPM then
      checks against the selected PCRs right away. Called without a digest, like
      tpm2_policypcr does here, the TPM just folds the current PCR values into the
      `policyDigest`, and whether they were the right ones only shows in the final
      comparison against `authPolicy`. In both variants, the TPM additionally records
      the current PCR update counter in the session as a deferred constraint: if PCRs
      are updated after the assertion, the session can no longer authorize anything.

### `PolicyAuthorize`

Locking against a PCR with `PolicyPCR` is super cool, but it is also brittle[^11]: At the
end of the previous section, a measurement changed, and our access expired with no way
to regain it. That is a problem, because PCR values change for legitimate reasons all
the time. Think of the passwordless disk unlock from the intro: the disk key is sealed
against the PCR state of the boot chain, and the next kernel update changes exactly
that state. The disk wouldn't unlock anymore, even though nothing bad happened, and we
certainly don't want to re-encrypt the disk on every update.

What would be nice to have instead is a policy that stays stable while the approved
state can change. Luckily, there is another mechanism that can be used to create a policy:
`PolicyAuthorize`. It introduces a level of indirection and delegation, allowing us to create a
policy from a public key instead of a system state. To authorize, you satisfy another, concrete
policy (like a `PolicyPCR`), then present a signature over the expected policy digest and a
`policyRef`. The concrete policy digest itself is not part of the policy. Whoever owns the
key can approve new concrete policies, offline. The `policyRef` scopes the signatures
so the signed policy can't be used out of context.

Let's create a RSA key pair to explore `PolicyAuthorize`:

```shell
openssl genrsa -out sign.key.pem 2048
openssl rsa -in sign.key.pem -pubout -out sign.pub.pem
```

Load the public key into the TPM so we can use it as part of a policy:

```shell
tpm2_loadexternal \
  --hierarchy=o \
  --key-algorithm=rsa \
  --public=sign.pub.pem \
  --key-context=signkey.ctx \
  --name=signkey.name
```
```
name: 000b028928264dd3d32fc9c10072d8f3e286ce20ef02c0873ecca601c3d4534b7661
```

The printed name is what will bind our policy to this key. And it is computed just like
the NV index names we saw earlier: as a digest over the object's public properties, which for
a key includes the public key itself. `tpm2_readpublic` shows these public properties:

```shell
tpm2_readpublic --object-context=signkey.ctx
```
```
name: 000b028928264dd3d32fc9c10072d8f3e286ce20ef02c0873ecca601c3d4534b7661
qualified name: 000b028928264dd3d32fc9c10072d8f3e286ce20ef02c0873ecca601c3d4534b7661
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: userwithauth|decrypt|sign
  raw: 0x60040
type:
  value: rsa
  raw: 0x1
exponent: 65537
bits: 2048
...
rsa: ...
```

Besides the name algorithm, the object attributes and the key parameters, the public
area contains the raw RSA modulus (shortened here). Any change to the public key changes
the name, and with it any policy created from that name.

Now use another trial session and the key name to create a policy that can be
authorized using this key:

```shell
printf 'demo' > policyref.bin
tpm2_startauthsession --session=trial.ctx
tpm2_policyauthorize --session=trial.ctx \
  --name=signkey.name \
  --qualification=policyref.bin \
  --policy=authorized.policy
tpm2_flushcontext trial.ctx
tpm2_flushcontext --transient-object
```
```
6120c875c3afb0b2811fc7c3c045c32fb53596e8009e96855ed4aa6c332d0bfb
```

The resulting policy digest contains no PCR value at all, it only depends on the
key name (and through it on the public key) and the `policyRef` label. As you
generated a different key pair, the policy hash you will get will differ, too.
Notice the second flush invocation with `--transient-object`: it removes the
key object that `tpm2_loadexternal` left behind in the TPM's limited
transient memory. tpm2-tools doesn't flush what it loads, so we
will repeat this cleanup after commands that load keys.
The printed policy hash is written to `authorized.policy`,
which we can then use to define our NV index again, similar to how we did it before:

```shell
tpm2_nvdefine 0x01000000 \
  --hierarchy=o \
  --hash-algorithm=sha256 \
  --attributes="nt=extend|authread|policywrite" \
  --policy=authorized.policy
```

For now, nobody can write this index, because no signature satisfying the policy exists yet.

In practice, this flow will usually have two parties: the key holder is for example
a team of distro maintainers. The individual machine is the other party that presents
evidence to its TPM. The key holder computes a concrete policy digest to approve,
for example a `PolicyPCR` for a specific build, then creates a signature over that digest
and the `policyRef`.

Create a new PCR policy for the updated value of PCR 15, that's what we want to bless now.
Like in the previous section we run a trial session to get a policy digest for the observed state:

```shell
tpm2_startauthsession --session=trial.ctx
tpm2_policypcr --session=trial.ctx \
  --pcr-list=sha256:15 \
  --policy=approved.policy
tpm2_flushcontext trial.ctx
```

Concatenate the policy and the policyRef:

```shell
cat approved.policy policyref.bin > tbs.bin
```

Then sign the whole thing with the private key:

```shell
openssl dgst -sha256 -sign sign.key.pem -out approved.sig tbs.bin
```

The policy and its signature can then be shipped to a machine, for example as part
of an image or update. This is the artifact showing the key holder approved this concrete
policy.

On the machine, we let the TPM verify the signature first:

```shell
tpm2_verifysignature --key-context=signkey.ctx \
  --hash-algorithm=sha256 \
  --message=tbs.bin \
  --scheme=rsassa \
  --signature=approved.sig \
  --ticket=verify.tkt
```

On successful verification, the TPM will return a ticket, which is an HMAC-stamped
proof[^12]. We can then start a new policy session, satisfy the concrete policy (the one
that we created the signature over), then present the ticket, the `policyRef` and
the policy to authenticate the session.

```shell
tpm2_startauthsession --session=s.ctx --policy-session
tpm2_policypcr --session=s.ctx --pcr-list=sha256:15
tpm2_policyauthorize --session=s.ctx \
  --input=approved.policy \
  --qualification=policyref.bin \
  --name=signkey.name \
  --ticket=verify.tkt
```

On the `tpm2_policyauthorize` call, the TPM ensures your session digest equals the
signed `approved.policy`, checks the ticket is valid for the given `policyRef` and
key, then swaps the current session digest to the authorize policy (`authorized.policy`).

Afterwards, the session digest matches the authorize policy we set during index definition,
and the session is unlocked:

```shell
tpm2_nvextend 0x01000000 \
    --hierarchy=0x01000000 \
    --auth=session:s.ctx \
    --input=m1.bin
tpm2_flushcontext s.ctx
tpm2_flushcontext --transient-object
```

With this construct, in case the PCR 15 measurement is changed by a future update, the index
is not bricked, it doesn't even need to be changed. The trusted key holder will just sign a
new policy matching the new PCR 15 state and ship that new policy as part of the update. On
the machine, the NV index with the same policy keeps working. This is exactly how systemd
keeps TPM-based disk unlock working across kernel updates: every UKI ships fresh signatures
matching its own expected PCR 11 state. But also keep the flip side of
this mechanism in mind: if the key holder only ever signs a single state, the policy is only
satisfiable while the machine is in exactly that state. We will exploit this in a moment.

### `PolicyOR`

A policy digest commits to one exact chain of assertions. All the elements are sequenced
via AND, we must match every element in order to get the expected session hash.
Sometimes we might want to construct an alternative branch instead, for example if we know
two good states, both of which we want to allow, or two different ways to authorize the same
operation. For this `PolicyOR` exists[^13]. The TPM will check
if the current session's digest is a member of the allowed list, then replace it in a similar
way it does when the `PolicyAuthorize` ticket is resolved. The policy is satisfied if one of
its branches is satisfied.

[^11]: The spec discusses the problem of "brittleness" in Section "16.7.11 Modification of Policies"
       in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture], and introduces a
       similar construction as we are about to build.
[^12]: Tickets are HMACs keyed with an internal TPM proof value, enabling the TPM to re-verify
       a signature later without loading the asymmetric key again, see "8.4.6.3 Tickets" in
       [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture]
[^13]: The digest replacement is illustrated in Section "16.7.4 Policy OR" in [TCG TPM 2.0 Library Specification, Version 185, Part 1: Architecture].

## Building a secure, policy-based NvPCR

With the previously introduced primitives, we can now take a look at how systemd
constructs a secure NvPCR. The NV index is protected by a write policy with two
branches that are connected with a `PolicyOR`: A `PolicyAuthorize` branch with a
public key and the `policyRef` `initrd`, and a `PolicyNvWritten(true)` branch.

Let's take a look at the `PolicyNvWritten(true)` branch first. This assertion allows
checking for the `written` attribute as part of a policy[^14]. So `PolicyNvWritten(true)` can be
satisfied without further authorization if the NvPCR has already been extended before. This is
the branch that is used after the initial setup, during runtime. At that point, extending
the NvPCR doesn't require additional authentication and can be done by any component with
access to the device.

The other branch, `PolicyAuthorize`, can be satisfied with a signed policy. This
branch must be used for the initial extend of the NvPCR. The concrete policy
used by systemd is a PCR policy for PCR 11, matching the expected state of that PCR
when running in the initrd during early boot. systemd tracks the boot phase in PCR 11:
When the initrd is started, `systemd-pcrphase-initrd.service` measures the event
`enter-initrd`. We construct the PCR policy against the expected state of PCR 11 after
this event. If the system hasn't been tampered with up to that point and the signature
is valid, the signed PCR policy is satisfied and the NvPCR can be initially extended.
When progressing to the next boot phase, the same service measures the phase event
`leave-initrd`. This locks the `PolicyAuthorize` branch for the rest
of the system lifetime. The NvPCR can then only be extended via the `PolicyNvWritten`
branch.

You might wonder why the write policy takes the indirection via `PolicyAuthorize`
instead of embedding the PCR policy directly. On a real system, PCR 11 doesn't only
contain the phase events: the UKI stub measures the kernel and initrd into it first,
so the initrd state of PCR 11 changes with every update. Embedded directly, every
update would change the write policy and with it the name of the index, and the NvPCR
would have to be recreated on every update. With `PolicyAuthorize`, the write policy
and the name stay stable, and only the signature shipped with the UKI changes.

Let's construct this final NvPCR version, similar to how systemd does it.
Measure the event that marks the start of the initrd boot phase, as done by
`systemd-pcrphase-initrd.service`:

```shell
echo -n "enter-initrd" | tpm2_pcrevent 11
tpm2_pcrread sha256:11
```
```
  sha256:
    11: 0xD15B0E8E244E65C40F024E95773F2347CE4EF3FFE6B597C9A14B50BBAB6DF319
```

<!-- author the write policy -->

Let's author the write policy.
The key from the previous section is reused. It takes the role of the UKI's PCR signing
key, whose public half is shipped in the `.pcrpkey` section of the UKI. First write the
`policyRef` with the value `initrd`[^15]. Then use a trial session to create the key-based
branch of the policy that must be used for the first write from within the initrd:

```shell
printf 'initrd' > initrd.ref
tpm2_startauthsession --session=trial.ctx
tpm2_policyauthorize --session=trial.ctx \
  --name=signkey.name \
  --qualification=initrd.ref \
  --policy=init.branch
tpm2_flushcontext trial.ctx
```

Next, create the second branch of the policy, the `PolicyNvWritten(true)`:

```shell
tpm2_startauthsession --session=trial.ctx
tpm2_policynvwritten --session=trial.ctx --policy=written.branch s
tpm2_flushcontext trial.ctx
```

And finally combine the two policies with a `PolicyOR`:

```shell
tpm2_startauthsession --session=trial.ctx
tpm2_policyor --session=trial.ctx \
  --policy-list=sha256:init.branch,written.branch \
  --policy=write.policy
tpm2_flushcontext trial.ctx
```

<!-- define the nvpcr -->

We use that policy to define the NvPCR, nearly identical to how we did before:

```shell
tpm2_nvdefine 0x01D10200 \
    --hierarchy=o \
    --hash-algorithm=sha256 \
    --attributes="nt=extend|policywrite|ownerread|authread|clear_stclear" \
    --policy=write.policy
tpm2_nvreadpublic 0x01D10200
```
```
0x1d10200:
    name: 000bf2e615c91fc1738ee23d6906f3cc5da932ed3d3dd19f99de0d0e0839712d8ecf
    ...
    attributes:
      friendly: policywrite|nt=0x1|ownerread|authread|clear_stclear
      value: 0x8060048
    size: 32
    authorization policy: A765636C5A04447BD790486F98DAF82CA694868DF19C1AF80632A52261E374EF
```

As the write policy depends on your generated key, your authorization policy and the index
name will again differ from mine. The only thing new here is the `clear_stclear` attribute:
It tells the TPM to clear the NV index on reboot[^16]. Similar to PCRs, the NvPCR should reset
on reboot, not persist measurements of a previous boot to the next. The `written` attribute
is also cleared on reset.

`0x01D10200` is the real handle from the NV index range systemd uses. Which NvPCRs exist on a
system is defined by small JSON files in `/usr/lib/nvpcr/*.nvpcr`, which since v262 must
be shipped as part of the UKI. systemd currently ships four definitions: `hardware` for the
product UUID, `cryptsetup` for the LUKS unlock mechanism used, `verity` for the root hashes
of activated verity volumes, and `login` for user logins[^17]. All four record events that are
unpredictable or unbounded in number, exactly the kind we don't want in the real PCRs.

<!-- vendor signing of initrd state -->

Then we craft the concrete PCR policy for the expected initrd state of PCR 11
and sign it together with the `policyRef`:

```shell
tpm2_startauthsession --session=trial.ctx
tpm2_policypcr --session=trial.ctx --pcr-list=sha256:11 --policy=initrd.policy
tpm2_flushcontext trial.ctx
cat initrd.policy initrd.ref > tbs.bin
openssl dgst -sha256 -sign sign.key.pem -out initrd.sig tbs.bin
```

In systemd, this is done at image build time with ukify. The tool gained a new flag `--sign-initrd-pcrs`
that precomputes the expected PCR 11 value for the `enter-initrd` phase and embeds the signed policy in the
UKI into a `.pcrsig` section.

<!-- initialize  -->

On each boot, systemd's `systemd-tpm2-setup-early.service` uses the signature and the
authorize policy path to initialize the NvPCR in the initrd. First, we let the TPM
verify the signature:

```shell
tpm2_verifysignature --key-context=signkey.ctx \
  --hash-algorithm=sha256 --message=tbs.bin --scheme=rsassa \
  --signature=initrd.sig --ticket=initrd.tkt
```

Then we start a policy session. We satisfy the PCR policy with the current state of PCR 11,
then call `tpm2_policyauthorize` to present the signature over the `initrd.policy`.
Finally, we call `tpm2_policyor` to present both branches and match the expected auth digest of
our NvPCR:

```shell
tpm2_startauthsession --session=s.ctx --policy-session
tpm2_policypcr --session=s.ctx --pcr-list=sha256:11
tpm2_policyauthorize --session=s.ctx --input=initrd.policy \
  --qualification=initrd.ref --name=signkey.name --ticket=initrd.tkt
tpm2_policyor --session=s.ctx --policy-list=sha256:init.branch,written.branch
```

With this session state, the policy is satisfied and we extend the NvPCR. systemd initializes
NvPCRs with all-zeros. The written value doesn't matter, the point is that the index gains the
`written` attribute, and that this first extend happened under the signed policy.

```shell
head -c 32 /dev/zero > zero.bin
tpm2_nvextend 0x01D10200 --hierarchy=0x01D10200 --auth=session:s.ctx --input=zero.bin
tpm2_flushcontext s.ctx
tpm2_flushcontext --transient-object
tpm2_nvread 0x01D10200 --size=32 | xxd -p -c 64
```
```
f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
```

Because the extended value is all-zeros, every freshly initialized SHA-256 NvPCR starts
out at this exact value, `SHA256(zeros32 || zeros32)`, on every machine. With the first
write done, the index gained the `written` attribute and thereby a new name:

```shell
tpm2_nvreadpublic 0x01D10200
```
```
0x1d10200:
    name: 000bf08c214c037f85d3520549dba23471a88af8aab1913bf269edfbb44b6d2de9f5
    ...
    attributes:
      friendly: policywrite|nt=0x1|ownerread|authread|clear_stclear|written
      value: 0x28060048
```

Keep this name in mind, we will get back to it in the next section.

<!-- leave the initrd -->

At the end of the initrd boot phase, systemd will measure the event marking the end of
that phase:

```shell
echo -n "leave-initrd" | tpm2_pcrevent 11
```

With this, the signed policy cannot be satisfied anymore until the next reboot!

<!-- runtime extension -->

Later at runtime, the write is authorized solely on the `written` property the NvPCR gained during
its initialization in initrd. This is what `systemd-pcrextend` does when it records an event, and
it requires no key and no secret, any component with access to the TPM can append. That is
deliberate: extends of real PCRs are unauthenticated, too, because adding history is harmless,
only rewriting it must be impossible.

```shell
tpm2_startauthsession --session=s.ctx --policy-session
tpm2_policynvwritten --session=s.ctx s
tpm2_policyor --session=s.ctx --policy-list=sha256:init.branch,written.branch
tpm2_nvextend 0x01D10200 --hierarchy=0x01D10200 --auth=session:s.ctx --input=m1.bin
tpm2_flushcontext s.ctx
tpm2_nvread 0x01D10200 --size=32 | xxd -p -c 64
```
```
5bbe1770fd46c5edfde5ef444b2d681d87925fcd71b1fe98c4f65749a6f3afb6
```

Notice that we still need to present both branches to the session, including the `init.branch`
digest. For that reason systemd persists it to `/run/systemd/nvpcr/<name>.auth` after
initialization.

Like for regular PCRs, systemd records each NvPCR measurement in its userspace
measurement log (`/run/log/systemd/tpm2-measure.log`), so that a verifier can later
replay the events and interpret the NvPCR value.

This concludes the hands-on part. When you are done experimenting, shut the software
TPM down:

```shell
kill "$(cat swtpm.pid)"
```

[^14]: While the policy commands run, the session isn't tied to any NV index yet, so the
      written property can't be checked immediately. `TPM2_PolicyNvWritten` extends
      the `policyDigest` like any other assertion, but additionally records the
      claimed written state in the session, as a deferred check. Only when the session is
      used to authorize a command does the TPM compare it against the actual attribute of
      the accessed index, and reject the command on mismatch.
[^15]: The real systemd implementation doesn't use the raw string as `policyRef`, but
      `SHA256("initrd")`, as the size of a policy ref is limited. The semantics are the same.
[^16]: More precisely, `clear_stclear` means the index is cleared on any `TPM2_Startup(CLEAR)`,
      which the platform issues on a TPM reset or TPM restart. Besides the reboot, that also
      covers resume from hibernation (not that Linux systems really hibernate with secure
      boot enabled). Resume from suspend on the other hand corresponds to `TPM2_Startup(STATE)`,
      a TPM resume, which preserves the index.
[^17]: If you inspect these indices on a real system, all but `hardware` will show one more
      attribute: `orderly`. An orderly NV index is backed by TPM RAM and only flushed to
      NVRAM on clean shutdown, sparing the NVRAM from wear on frequently written indices
      like `login`. TPM RAM is even scarcer than NVRAM, though, so the `hardware` NvPCR,
      written only once per boot, isn't using it. And as `orderly` is an attribute, it is part
      of the index name.

## Security considerations of the NvPCR design

Let's take a look at the security this construction is providing us with. The attacker
we are looking at gains access during runtime of the system, after the `leave-initrd`
event is measured, and wants to rewrite the NvPCR history unnoticed, like Alice hiding
her login in that naive index attack from the beginning.
They have root privilege and can access the TPM to read, write, undefine
and redefine NV indexes, extend (but not reset) PCRs. They can also reboot or boot a
different OS. Attacks against the TPM hardware itself are out of scope.

The TPM itself is trusted, and so is the measured boot chain up to and including the
initrd, including firmware, bootloader and UKI. The initrd is authorized to initialize
NvPCRs by design, which is expressed by the signed policy over the initrd state of
PCR 11. But PCR 11 is under OS control, a different kernel could extend the
expected values and reach the authorized state, too. It takes the firmware-controlled
PCRs, which record the bootloader and UKI that actually ran, to tie the initrd state
of PCR 11 to the initrd we trust. Booting anything else is visible to the verifier.
We also have to trust the key holder, as whoever controls the PCR signing key can bless
arbitrary states, and the verifier, which has to check more than just the NvPCR values,
as we will see below.

The write policy and the public key are no secrets, so the attacker can undefine our
NvPCR and redefine it, byte-for-byte identical. To replay a history, the attacker then
has to perform the first write to the fresh index, and both branches of the write
policy refuse: The `PolicyNvWritten(true)` branch can't authorize the write. Nothing
stops the attacker from running the policy commands, and the session digest will even
match the write policy, but the deferred written-check fails against the never-written
index, and the TPM rejects the extend. And the `PolicyAuthorize` branch fails, too: the only
signature in existence approves the initrd state of PCR 11, which the machine left
when `leave-initrd` was measured. The session can't reach the signed digest anymore,
so the TPM rejects and the attacker isn't able to create a forged history.

There is one more signature the attacker might try: the same key also signs the UKI's
other PCR policies, for example the ones used for disk unlock, and some of those are
satisfiable in the runtime state of the machine. This is where the
`policyRef` comes in: our authorize branch only accepts signatures made for the ref
`initrd`, and the other policies are signed with a different ref (or none at all).
The signatures are not interchangeable.

Of course, the attacker doesn't have to reuse our write policy. They can redefine the
index with `authwrite`, like our naive index from the beginning, and replay whatever
history they like. But remember that the name of an NV index is a hash over all of its
public properties: the attributes and the write policy, which in turn commits to the
vendor's public key. There is no way to create an index that is writable outside the
initrd without ending up with a different name.

This makes the name the anchor of the whole design, and the last missing piece is
making it verifiable. After initializing an NvPCR, systemd extends the event
`nvpcr-init:<name>:0x<handle>:<tpm-name>` into PCR 9, a real, non-resettable PCR.
It is the cheapest PCR to sacrifice: the kernel measures into it every initrd it is
handed, which on a UKI boot is a concatenation of the UKI's embedded initrd with cpio
archives that systemd-stub generates on the fly, for example for credentials, all mangled
into a single value, on some setups joined by verbose bootloader records. This makes
PCR 9 hard to predict, so no unlock policy can bind to it anyway, while the measurement
that matters, the UKI initrd, is already cleanly covered by PCR 11.
Once all NvPCRs are initialized, `systemd-pcrnvdone.service` measures a separator
event `nvpcr-separator` into PCR 9, still inside the initrd. The NvPCR values themselves
are attested with `TPM2_NV_Certify`, which has the TPM sign the current index contents
together with the index name. The new [systemd-report-sign-tpm2] signer emits these
attestations alongside regular PCR quotes. A verifier doing remote
attestation must only trust NvPCR values whose attested index name matches an
`nvpcr-init` event that appears before the separator in the PCR 9 event log. Any
recreated index fails this check: wrong name, or right name but logged after the
separator.

Two capabilities of our attacker are left: rebooting and booting a different OS. A
reboot resets the NvPCRs just like the real PCRs, and the next boot re-initializes them
in the initrd. The attacker gains nothing: the new boot is a genuine one, its history
starts fresh by design, and the verifier can see that a reboot happened. Booting a
different OS doesn't help either, as it produces different measurements in PCR 11 and
the other boot chain PCRs. The signed policy can't be satisfied, and any quote produced
from such a boot exposes the manipulated boot chain.

[systemd-report-sign-tpm2]: https://github.com/systemd/systemd/pull/42957

## Conclusion

An NvPCR in systemd v262 is an NV extend index whose first write is gated by a signed
PCR policy that can only be satisfied in the initrd, while all later writes are free. The
index name, measured into PCR 9 during early boot, anchors the construction for verifiers:
any index recreated with a weaker write policy carries a different name and is detected.
We reconstructed such an NvPCR on the command line and discussed why an attacker can't
forge measurements: once the initrd window has closed, no road into the write policy of a
fresh index remains, and everything the attacker can still do is destructive and shows up
in attestation.

A practical note to close with: The write policy is based on the UKI's PCR signing key.
When that key rotates, systemd-tpm2-setup detects the name mismatch, checks that the
existing index looks like an NvPCR, and recreates it with the new policy. The same path
automatically upgrades NvPCRs created by the pre-v262 design, so the roll-out to your
systems will happen automatically with the systemd update.

The initrd-bound signed policy turns out to be useful beyond NvPCRs, too. With
`systemd-cryptenroll --tpm2-public-key-policyref=initrd`, you can enroll LUKS keyslots
that can only be unlocked from the initrd. And if you want to see all of this on a real
system, boot a v262 image with a UKI built with `--sign-initrd-pcrs` and take a look at
`systemd-analyze nvpcrs` and the PCR 9 event log.

---

## Thanks

*To my colleague at Amutable [Chris Coulson], who authored the new NvPCR design and gave insightful
corrections and additions to this blog post. Linux security work in the upstream projects
we all rely on is at the heart of our mission at Amutable: [building new secure foundations].*

[building new secure foundations]: https://amutable.com/blog/building-new-secure-foundations
[Chris Coulson]: https://mstdn.social/@chrisccoulson
## References

- [Add support for nvindex-based additional PCRs for TPM2, aka "NvPCRs"](https://github.com/systemd/systemd/pull/39463) PR on systemd
- [tpm2: Improve how NvPCR protection works](https://github.com/systemd/systemd/pull/42796) PR on systemd
- [TPM2 PCR Measurements Made by systemd](https://systemd.io/TPM2_PCR_MEASUREMENTS/) documentation
- [TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) (Section "Latest Version")
- [tpm2-tools man pages](https://github.com/tpm2-software/tpm2-tools/tree/master/man)
