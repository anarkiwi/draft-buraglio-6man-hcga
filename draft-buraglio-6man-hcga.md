---
title: "Hierarchical Cryptographically Generated Addresses (HCGA)"
abbrev: "Hierarchical Cryptographically Generated Addresses (HCGA)"
category: std

docname: draft-buraglio-6man-hcga-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: INT
workgroup: 6man
keyword:
 - hcga
 - ipv6
 - Internet-Draft
venue:
  group: 6man
  type: Working Group
  mail: ipv6@ietf.org
  arch: https://datatracker.ietf.org/wg/6man/about/
  github: buraglio/draft-buraglio-6man-hcga
  latest: https://github.com/buraglio/draft-buraglio-6man-hcga

author:
 -
    fullname: Nick Buraglio
    organization: Energy Sciences Network
    email: buraglio@forwardingplane.net

normative:
  RFC2119:
  RFC8174:
  RFC4291:
  RFC3972:
  RFC4581:
  RFC4982:
  RFC5480:
  RFC6234:

informative:
  RFC3971:
  RFC4271:
  RFC7217:
  RFC8200:
  RFC8981:
  RFC9334:
  RFC9582:
  WIMSE-ARCH:
    title: Workload Identity in a Multi System Environment (WIMSE) Architecture
    author:
      - ins: J. Salowey
      - ins: Y. Rosomakho
      - ins: H. Tschofenig
    seriesinfo:
      Internet-Draft: draft-ietf-wimse-arch-08
    date: 2026
  TRANSITIVE-ATTEST:
    title: Transitive Attestation for Sovereign Workloads
    author:
      - ins: G. Mandyam
      - ins: J. Walker
    seriesinfo:
      Internet-Draft: draft-mw-wimse-transitive-attestation-00
    date: 2026
  RATS-KEY-ATTEST:
    title: Evidence Encoding for Hardware Security Modules
    author:
      - ins: J.-P. Fiset
      - ins: M. Ounsworth
      - ins: H. Tschofenig
      - ins: H. Birkholz
      - ins: M. Wiseman
      - ins: N. Smith
    seriesinfo:
      Internet-Draft: draft-ietf-rats-pkix-key-attestation-07
    date: 2026
  WIMSE-AIMS:
    title: AI Identity Management System
    author:
      - ins: P. Kasselman
      - ins: J. Lombardo
      - ins: Y. Rosomakho
      - ins: B. Campbell
      - ins: N. Steele
      - ins: A. Parecki
    seriesinfo:
      Internet-Draft: draft-ietf-wimse-aims-00
    date: 2026
  ANCHOR-PoC:
    title: "ANCHOR: Agent Network Cryptographic Hardware Origin Recording"
    author:
      - name: Nick Buraglio
    date: 2026
    target: https://github.com/buraglio/anchor
  SPIRE:
    title: SPIRE
    author:
      - org: SPIFFE Project
    target: https://github.com/spiffe/spire
  KATA:
    title: Kata Containers
    author:
      - org: Kata Containers Project
    target: https://katacontainers.io
  KEYLIME:
    title: Keylime
    author:
      - org: Keylime Project
    target: https://keylime.dev

---

--- abstract

RFC 3972 defines Cryptographically Generated Addresses (CGA), in which the
Interface Identifier (IID) of an IPv6 address is derived from a cryptographic
public key. The /64 subnet prefix is supplied by network infrastructure and
has no cryptographic relationship to the key. This document specifies
Hierarchical CGA (HCGA), an extension to RFC 3972 that also derives part of
the upper 64 bits — specifically the bits between the organizational prefix
and the /64 boundary — from the same public key. The result is an address
whose full 128-bit value is a deterministic function of a public key
(typically hardware-bound), an operator-controlled aggregate prefix, and
two modifiers. HCGA is a traceability component intended for use within a
larger accountability architecture that supplies key attestation, parameter
distribution, and source-address enforcement; that architecture is not
specified here. The capability supports workload network accountability in
multi-tenant environments such as Kubernetes clusters, where
infrastructure-assigned prefixes provide no per-instance cryptographic binding.

---

--- middle

## 1. Introduction

RFC 3972 {{RFC3972}} provides a mechanism to bind an IPv6 host's network
address to a public key by deriving the 64-bit Interface Identifier (IID)
from a cryptographic hash of the key. This binding enables Secure Neighbor
Discovery {{RFC3971}} and is used by ANCHOR {{ANCHOR-PoC}} as the primary
forensic accountability signal.

RFC 3972 treats the /64 prefix as a trusted external input from network
infrastructure. For hosts with a single, stable interface on a
well-administered network, that assumption holds. For containerized and
virtualized workloads, however, the prefix is assigned by an orchestration
layer (CNI plugin, cloud provider, or hypervisor) and has no cryptographic
relationship to the workload's identity.

This gap matters for agentic accountability in two concrete ways:

1. **Multiple agents per prefix.** Thousands of agentic instances may share
   a single /64 (e.g., all pods on a node subnet). The IID distinguishes
   instances within the prefix, but the prefix itself is a coarse-grained
   infrastructure artifact with no binding to any particular workload key.

2. **Per-agent routing granularity.** Routing and monitoring operate at
   prefix granularity. If each agent has its own cryptographically-identified
   /64, routing tables can carry per-agent policy without per-agent
   configuration — the prefix encodes the identity.

HCGA extends RFC 3972 by deriving the lower bits of the /64 prefix — the
"subnet bits" between the organizational aggregate and the /64 boundary —
from the same public key as the IID. The result is a two-level cryptographic
hierarchy:

- The /64 subnet identifies the agent at the routing level.
- The IID provides the RFC 3972 address-level binding within that subnet.

Together, the full 128-bit address is a deterministic, verifiable function of
the hardware key, the operator-controlled aggregate prefix, and the RFC 3972
modifier. HCGA operates at the network layer and is designed as a complement
to application-layer workload identity mechanisms such as the WIMSE
architecture {{WIMSE-ARCH}} and the AI Identity Management System
{{WIMSE-AIMS}}, which address authentication and authorization of AI agent
interactions above the IP layer.

HCGA is one component of a larger accountability architecture and is not
useful in isolation. This document specifies only the address derivation
and verification functions. It assumes, and does not specify, a surrounding
architecture that (a) attests the public key and its protection (see §9.5),
(b) conveys the HCGA parameters (public key, modifier, prefix modifier) to
verifiers, (c) binds packets or sessions to the key, for example through
signed neighbor discovery {{RFC3971}} or a transport- or application-layer
signature, and (d) enforces source-address validity within the aggregate.
The forensic value of an HCGA address is bounded by the weakest of these.
{{ANCHOR-PoC}} is one such architecture.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

**Aggregate Prefix (A):** An IPv6 prefix of length L (L < 64), operator-
controlled, announced via BGP. All HCGA-derived addresses are within A.
Typical length: /48.

**Subnet bits:** The bits from position L through position 63 inclusive
(0-indexed from the MSB). Bit count: 64 − L. For a /48 aggregate, the
subnet bits occupy positions 48–63, a 16-bit field.

**Pod prefix / HCGA prefix:** The /64 derived by appending the subnet bits
to the aggregate prefix.

**CGA params:** As defined in RFC 3972: modifier (128-bit random value),
subnet prefix, collision count, public key (SPKI format), and optional
extension fields {{RFC4581}}.

**Prefix modifier (PM):** A 128-bit value, chosen by the generating node,
used to resolve /64 prefix collisions (§5.7). It is an HCGA parameter
conveyed alongside the CGA params by the surrounding architecture; it is
not part of the RFC 3972 CGA Parameters data structure.

**SPKI:** SubjectPublicKeyInfo, the DER-encoded format for a public key.
[RFC3972] specifies this encoding for RSA keys; this document uses it with
ECDSA keys as defined in [RFC5480].

## 3. RFC 3972 Background

[RFC3972] §5 defines the CGA IID generation procedure in terms of two
hashes over the CGA Parameters data structure:

```
CGA_Params = modifier[16] || subnet_prefix[8] || collision_count[1]
             || public_key_SPKI || extension_fields
Hash1 = H(CGA_Params)[:8]
Hash2 = H(modifier[16] || 0x00^9 || public_key_SPKI || extension_fields)

IID = Hash1
IID[0] = (IID[0] & 0x1C) | (Sec << 5)
         # bits 0-2 := Sec; bits 6 and 7 (u/g) := 0
```

where `subnet_prefix[8]` is the first 8 bytes of the /64 prefix, `Sec` is
a 3-bit security parameter encoded in the leftmost bits of the IID, and
the 16×Sec leftmost bits of `Hash2` are required to be zero (the modifier
is incremented until this holds). The collision count takes the values 0,
1 or 2 and is incremented on duplicate address detection failure.

Verification works in reverse: given `(address, CGA_Params)`, check that
`subnet_prefix` equals bits 0–63 of the address, recompute `Hash1` and
compare it against `address[8:16]` ignoring the Sec and u/g bits, and
check the `Hash2` zero-bit condition for the Sec value read from the
address.

[RFC3972] uses SHA-1 for `H`. [RFC4982] provides hash agility by having
the Sec value identify both the hash function and the security parameter,
via the IANA "CGA SEC" registry. HCGA uses SHA-256 for `H` under a Sec
value assigned per that registry (§10.1), with security parameter 0.

## 4. Problem Statement

### 4.1 Infrastructure-Assigned Prefixes Carry No Key Binding

In RFC 3972 deployments, the /64 prefix is external. Consider a Kubernetes
node with prefix `3fff:1:cafe:1::/64` assigned by the CNI plugin. All pods
on that node share the same /64. Each pod generates a CGA IID from its own
key and the shared prefix, producing unique addresses within the /64.

In this scenario, each pod gets a unique, verifiable address within the
/64. The limitation is that the prefix itself is a network infrastructure
artifact — it identifies the node or node subnet, not the individual agent.
The prefix alone carries no cryptographic relationship to any particular
workload key.

### 4.2 Per-Agent /64 Routing

A network operator managing a large agentic deployment may prefer or be required by policy to provide per-agent
routing policy on order to provide technical features such as rate limiting, traffic engineering, QoS, and monitoring. If each
agent is provisioned with its own /64, those policies are able to map directly to routing table entries.
Infrastructure-assigned prefixes require an external table to connect an
address to an agent; hardware-derived prefixes carry that mapping in the
address itself.

### 4.3 Multiple Addresses per Agent

CGA allows a host to derive multiple addresses from the same key with
different modifiers. In [RFC3972], all such addresses share the same /64.
In HCGA, the agent owns the /64 entirely — it may derive addresses with
any IID within its /64, enabling per-connection address pseudonymity while
retaining per-agent /64 accountability.

## 5. HCGA Specification

### 5.1 Parameters

HCGA takes the following inputs:

- **public_key**: ECDSA P-256 public key, SPKI DER encoded
- **modifier**: 128-bit value (as in RFC 3972; see §5.7 and §6)
- **prefix_modifier**: 128-bit value, initially random (see §5.7)
- **aggregate**: IPv6 prefix of length L, where L < 64 (operator-controlled)
- **hash_alg**: SHA-256 (required for this profile)
- **Sec**: the CGA SEC value assigned to this profile (TBD1, §10.1)

### 5.2 Subnet Bit Derivation

Let `n = 64 - L` be the number of subnet bits, and `aggregate_bytes[8]`
the first 8 bytes of the aggregate prefix with bits L through 63 set to
zero.

```
subnet_hash = SHA-256(aggregate_bytes[8] || prefix_modifier[16]
                      || public_key_SPKI_DER)
subnet_bits = subnet_hash[0:n]      # leftmost n bits
```

For a /48 aggregate (n = 16), `subnet_bits` is the first two bytes of
`subnet_hash`.

For non-byte-aligned cases (n not divisible by 8), the leftmost `n` bits of
the hash are used and placed at bit positions L through 63 of the prefix;
no bits of the hash beyond position n−1 contribute.

Including the aggregate in the hash input separates derivations under
different aggregates; including the prefix modifier allows a node whose key
yields a prefix already in use to derive a different prefix without
changing its key.

### 5.3 HCGA Prefix Construction

```
hcga_prefix_bits = aggregate_bits[0:L] || subnet_bits[0:n]
hcga_prefix      = IPv6 prefix of length 64 formed from hcga_prefix_bits
```

Equivalently, in GoLang notation:
```go
var prefixBytes [8]byte
aggBytes := aggregate.Masked().Addr().As16()
copy(prefixBytes[:], aggBytes[:L/8])
h := sha256.New()
h.Write(aggBytes[:8])
h.Write(prefixModifier[:])
h.Write(publicKeySPKIDER)
subnetHash := h.Sum(nil)
if L%8 == 0 {
    // Byte-aligned: copy hash bytes directly
    for i := L / 8; i < 8; i++ {
        prefixBytes[i] = subnetHash[i-L/8]
    }
} else {
    // Non-byte-aligned: shift hash bits to align with address bit boundary
    shift := uint(L % 8)
    mask := byte(0xFF) << (8 - shift)
    prefixBytes[L/8] = (aggBytes[L/8] & mask) | (subnetHash[0] >> shift)
    for i := L/8 + 1; i < 8; i++ {
        j := i - L/8 - 1
        prefixBytes[i] = (subnetHash[j] << (8 - shift)) | (subnetHash[j+1] >> shift)
    }
}
```

### 5.4 IID Derivation

The IID is computed per [RFC3972] §5, with the hash function and Sec value
given by [RFC4982] for the CGA SEC value TBD1, using `hcga_prefix` as the
subnet prefix input:

```
CGA_Params = modifier[16] || hcga_prefix_bytes[8] || collision_count[1]
             || public_key_SPKI_DER
Hash1 = SHA-256(CGA_Params)[:8]
IID   = Hash1
IID[0] = (IID[0] & 0x1C) | (TBD1 << 5)
```

where `hcga_prefix_bytes[8]` is the 8-byte representation of the /64
network address (i.e., the first 8 bytes of a 128-bit address formed by
appending 64 zero bits to `hcga_prefix`), and `collision_count` is the
RFC 3972 collision count (0, 1 or 2; see §5.7). The leftmost three bits of
the IID carry the Sec value and bits 6 and 7 are cleared, exactly as in
RFC 3972.

Because the security parameter associated with TBD1 is 0, the RFC 3972
`Hash2` condition (16×0 = 0 leading zero bits) is satisfied for every
modifier and no modifier search is needed at generation time.

This is identical to {{RFC3972}} §5 as extended by {{RFC4982}}, with
`hcga_prefix` substituted for the externally-provided prefix.

### 5.5 HCGA Address Construction

```
hcga_address = hcga_prefix :: IID
```

The resulting 128-bit address has:
- Bits 0 to L−1: operator-controlled aggregate prefix (fixed, BGP-announced)
- Bits L to 63: leftmost 64−L bits of
  `SHA-256(aggregate || prefix_modifier || public_key)` — key-derived subnet bits
- Bits 64 to 127: RFC 3972/4982 IID — key-derived, modifier-randomized

### 5.6 Verification Procedure

Given `(hcga_address, CGA_Params, prefix_modifier)`, where `CGA_Params`
carries the modifier, subnet prefix, collision count and public key:

1. **Aggregate check:** verify that bits 0 to L−1 of `hcga_address` match
   the operator's aggregate prefix. This is a routing-level check, performed
   before cryptographic verification.

2. **Subnet bit check:** compute `subnet_hash` per §5.2 from the aggregate,
   `prefix_modifier` and the public key, and verify that bits L to 63 of
   `hcga_address` match bits 0 to (63−L) of the hash.

3. **IID check:** perform the [RFC3972] §5 verification procedure on
   `(hcga_address, CGA_Params)` using the hash function and security
   parameter given by [RFC4982] for the Sec value read from the address.
   This includes checking that the subnet prefix in `CGA_Params` equals
   bits 0–63 of `hcga_address`, that the collision count is 0, 1 or 2, and
   that `Hash1` matches bits 64–127 ignoring the Sec and u/g bits. If the
   Sec value is not TBD1 the address is not an HCGA address under this
   profile.

All three checks MUST pass for the address to be considered a valid HCGA
address. Failure of any check MUST be treated as a verification failure.

Note that step 3 is exactly RFC 3972/4982 verification. A verifier that
implements [RFC4982] and recognizes Sec value TBD1 therefore validates the
IID without any knowledge of HCGA; only step 2 requires this specification.

### 5.7 Collision Handling

Two independent values are used to resolve collisions:

- **Collision count** (IID collisions within the /64): on duplicate address
  detection failure, the collision count is incremented and the IID
  recomputed, exactly as in [RFC3972] §5 steps 6–8. The modifier is not
  changed for this purpose. After three collisions generation fails, per
  RFC 3972.

- **Prefix modifier** (/64 collisions within the aggregate): if the derived
  `hcga_prefix` is already in use by a different key within the aggregate,
  the generating node MUST increment `prefix_modifier` (as a 128-bit
  unsigned integer, modulo 2^128) and recompute §5.2 through §5.4. How
  prefix use is detected (for example, by querying a registry maintained by
  the surrounding architecture, or by prefix-level duplicate detection on
  the fabric) is outside the scope of this document.

The probability that a freshly derived /64 collides with one of n existing
prefixes in a /48 aggregate is approximately n/2^16, and the expected number
of prefix-modifier retries is correspondingly small while n ≪ 2^16. The
subnet field cannot hold more than 2^(64−L) prefixes; operators SHOULD
choose L so that 2^(64−L) comfortably exceeds the expected number of
simultaneously active keys (for example, L ≤ 32 for deployments of tens of
thousands of workloads).

The modifier plays no role in collision resolution under this profile; it
is used only to derive multiple addresses within a /64 (§6).

## 6. Multiple HCGA Addresses per Agent

The HCGA prefix depends on the public key and prefix modifier but not on
the modifier, while the IID depends on all of these. An agent can therefore
derive multiple valid addresses within the same /64 by varying the
modifier (RFC 3972 places no constraint on how the modifier is chosen
beyond the Hash2 condition, which is vacuous under this profile). This
enables:

- Per-connection pseudonymity: each outbound connection uses a different
  IID (different modifier), making traffic correlation within the /64
  more difficult for passive observers.
- Connection-level accountability: the registry maps the HCGA prefix
  to the agent; the specific IID is per-connection context.

Multiple addresses per agent do not affect forensic accountability: any
address in the agent's /64 is attributable to the same hardware key via
the prefix verification step.

## 7. Interaction with RFC 3972 CGA Parameters

HCGA reuses the [RFC3972] CGA parameter structure (modifier, subnet prefix,
collision count, public key) directly, with one substitution:

- **modifier**: unchanged, per RFC 3972
- **subnet prefix**: set to `hcga_prefix` (the derived /64), not the
  aggregate — this allows RFC 4982-capable verifiers to validate the IID
  given the /64, without knowledge of HCGA
- **collision count**: unchanged, per RFC 3972
- **public key**: unchanged, per RFC 3972

The prefix modifier is not carried in the CGA Parameters structure and is
conveyed separately (§2). A verifier given `(hcga_address, cga_params)`
that implements [RFC4982] and recognizes Sec value TBD1 will correctly
validate the IID with `hcga_prefix` as the subnet prefix. A verifier that
implements only [RFC3972], or that does not recognize TBD1, will reject the
address, because the hash function differs from SHA-1. No verifier can
check that `hcga_prefix` is itself derived from the public key without
the prefix modifier and this specification.

## 8. Routing Considerations

### 8.1 Aggregate Announcement

The autonomous system operating the ANCHOR deployment MUST announce the
aggregate prefix A via BGP {{RFC4271}}, covered by an RPKI ROA {{RFC9582}}.
Per-/64 routes are not announced externally; they remain internal to the
cluster or network segment. External observers see only the aggregate,
as with any provider-independent prefix assignment.

### 8.2 Intra-Cluster Routing

Within a Kubernetes cluster or datacenter fabric, the CNI plugin (Calico,
Cilium with BGP enabled) installs per-/64 routes for active agents. Each
agent's HCGA /64 is programmed as a host route into the pod's network
namespace.

### 8.3 RPKI Alignment

The aggregate ROA covers all HCGA addresses by containment. No per-/64 ROA
is needed — RPKI operates at the granularity of BGP announcements, and
per-/64 routes are never advertised externally. The full accountability
chain `ROA(aggregate) → ASN → aggregate → HCGA /64 → IID` is verifiable
without any additional RPKI infrastructure.

## 9. Security Considerations

### 9.1 Scope and Threat Model

HCGA binds an address to a public key; it does not by itself prove that a
given packet was sent by the holder of that key. As with RFC 3972 (see
RFC 3972 §7.1), an HCGA address is only meaningful as evidence when
combined with a signature made with the corresponding private key, or with
network-layer enforcement that prevents other nodes from sourcing packets
from that address. Both are the responsibility of the surrounding
architecture (§1). An HCGA address presented without such a binding is a
claim, not evidence.

Verification (§5.6) requires the modifier, collision count, public key and
prefix modifier. HCGA does not specify how a verifier obtains these; in
[RFC3971] they are carried in neighbor discovery options and are therefore
available only on-link. A forensic verifier operating off-link depends on
the surrounding architecture to have recorded the parameters at generation
time. Without such a record, no verification is possible and the address
carries no more information than any other address in the aggregate.

### 9.2 Subnet Bit Security

The subnet bits are the leftmost n = 64−L bits of a SHA-256 output. The
binding between a /64 prefix and a key is therefore n bits strong, not 256
bits strong. In particular, for a /48 aggregate an attacker who wishes to
derive a valid HCGA address inside a victim's /64 needs only to generate
candidate key pairs (or candidate prefix modifiers for a key of their own)
until the 16-bit subnet hash matches — approximately 2^16 trials, which is
trivial. The subnet bits do not prevent a second key from occupying a
given /64; they only make it impossible for an address to be a valid
HCGA address without some key that hashes to its prefix.

Consequently, the forensic claim "this /64 belongs to key K" cannot be made
from the address alone. It can only be made by a verifier that holds a
record, established at generation time by the surrounding architecture,
of which key (and prefix modifier) was admitted to that /64, and that
enforces exclusivity (§5.7). The value HCGA adds over an opaque registry
mapping is that the record is self-checking: a mismatch between the
recorded parameters and the address is detectable, so a registry entry
cannot be silently re-pointed at a different key. The subnet bits also
allow per-/64 policy to be applied before any registry lookup, at the cost
of the squatting exposure above.

The same bound applies to the IID: with security parameter 0 the IID is 59
bits of hash output and an attacker can find a key producing any chosen IID
within a chosen /64 in roughly 2^59 trials, as for an RFC 3972 address with
Sec = 0.

The subnet bits expose partial information about the public key —
specifically, a truncated hash output — which is equivalent in kind to
what the RFC 3972 IID already reveals. No additional key material is
exposed.

### 9.3 Privacy Implications

Compared to RFC 3972 CGA, HCGA addresses are more linkable in one respect:
the /64 subnet is stable across IID rotations (modifier changes). Any two
HCGA addresses that share the same /64 are attributable to the same hardware
key, even without inspecting the IID. This is intentional for agentic
accountability, but it may be inappropriate for privacy-sensitive deployments.
Operators MUST assess this tradeoff before using HCGA for traffic involving
personal data.

Multiple HCGA addresses per agent (§6) provide IID-level pseudonymity but
not /64-level pseudonymity — the /64 is permanently bound to the hardware
key. This linkability is stronger than that of temporary addresses {{RFC8981}},
which rotate both the IID and (in some deployments) the prefix. Operators
should weigh RFC 8981 semantics carefully before deploying HCGA where
individual privacy is a concern.

### 9.4 IPR Status of RFC 3972

RFC 3972 carries IETF IPR disclosures (ipr/676, KAME). Any standards-track
work extending RFC 3972 must address these encumbrances. This document takes
no position on IPR; that determination belongs to the IETF Standards Process.

### 9.5 Hardware Root of Trust Scope

The security properties of HCGA depend on the hardware root of trust used
for the underlying key pair:

- **Hardware TPM 2.0 (physical):** non-extractable private key; maximum
  binding strength
- **vTPM (VM-bound):** bounded by hypervisor isolation; attestation via TDX/SEV-SNP
- **SPIFFE SVID key pair:** software-generated, rotated; no direct hardware binding;
  chain via SPIRE tpm_devid node attestation
- **Software key (stub mode):** no hardware binding; development use only

HCGA verification does not encode attestation tier; the mechanism binds
an address to a public key regardless of how that key is protected. Relying
parties SHOULD obtain and verify attestation evidence alongside the HCGA
address to determine the strength of the underlying key binding. The RATS
architecture {{RFC9334}} provides the framework for remote attestation
evidence conveyance; {{RATS-KEY-ATTEST}} addresses hardware key attestation
for HSMs and TPMs. For SPIFFE-chained deployments, {{TRANSITIVE-ATTEST}}
addresses transitive attestation across workload boundaries.

## 10. IANA Considerations

### 10.1 CGA SEC Value

[RFC4982] establishes the "CGA SEC" registry, in which each Sec value
identifies a hash function and a security parameter. This document
requests the assignment of one value from that registry:

| Sec value | Hash function | Security parameter | Reference |
|---|---|---|---|
| TBD1 | SHA-256 | 0 | This document |

The assigned value is to replace "TBD1" throughout this document. The
public key type is not encoded in the Sec value; this profile uses ECDSA
P-256 keys as described in §5.1.

### 10.2 CGA Parameters Extension

No new CGA Parameters extensions are required. This document passes
`hcga_prefix` as the `subnet_prefix` field in the existing CGA Parameters
structure, and conveys the prefix modifier outside that structure (§2).

---

--- back

# Appendix A: Example HCGA Derivation (ECDSA P-256, /48 Aggregate)

This example uses Sec = 3 as an assumed value for TBD1; the vector will be
regenerated once IANA assigns the value. The key is derived from a fixed
scalar so that the vector is reproducible; it MUST NOT be used in
production.

Given:
- aggregate: `3fff:1:cafe::/48` (L = 48, n = 16)
- ECDSA P-256 private scalar d (hex):
  `3c7d964d5fe2da80544713c9312c5203ac4569111f3f063c6e2dacd5721acb01`
- public key, SPKI DER (91 bytes, hex):
```
3059301306072a8648ce3d020106082a8648ce3d03010703420004d93d035f38
f4414da99b65c170f24a0d72e962a84f6b42f2f32fa06bf99d4b2468776b5fb7
bb958b60aa9e0b4c7b60ce82b0e9a1dbd2baf5457e850b31f93435
```
- prefix_modifier: 16 zero bytes
- modifier: 16 zero bytes
- collision_count: 0x00

Step 1 — Subnet bits (16 bits for /48 → /64):
```
aggregate_bytes = 3f ff 00 01 ca fe 00 00
subnet_hash = SHA-256(aggregate_bytes || prefix_modifier || SPKI_DER)
            = 6633525504192ef7d5fe7fef4de9fe103d499fca1e1c5cb3d71c2e462e620c87
subnet_bits = 0x6633
```

Step 2 — HCGA prefix:
```
hcga_prefix = 3fff:1:cafe:6633::/64
```

Step 3 — IID:
```
hcga_prefix_bytes = 3f ff 00 01 ca fe 66 33
CGA_Params = modifier[16] || hcga_prefix_bytes[8] || 0x00 || SPKI_DER
Hash1[:8]  = b7 b2 a1 62 23 12 55 ab
IID[0]     = (0xb7 & 0x1C) | (3 << 5) = 0x74
IID        = 74 b2 a1 62 23 12 55 ab
```

Step 4 — HCGA address:
```
3fff:1:cafe:6633:74b2:a162:2312:55ab
```

Verification:
1. Aggregate check: `3fff:1:cafe::/48` → matches operator's /48 ✓
2. Subnet check: `SHA-256(aggregate_bytes || prefix_modifier || SPKI_DER)[0:2] = 0x6633`
   → matches bits 48–63 ✓
3. IID check (RFC 3972/4982, Sec = 3 → SHA-256, security parameter 0):
   subnet prefix in CGA_Params = bits 0–63 ✓; collision count 0 ✓;
   Hash1 = `b7b2a162231255ab` matches `74b2a162231255ab` ignoring bits 0–2
   and 6–7 ✓; Hash2 requires 0 leading zero bits ✓


# Appendix B: Go Implementation Sketch

```go
// DeriveHCGAPrefix derives the /64 HCGA prefix from an aggregate, a prefix
// modifier and a public key. aggregate must be a /L prefix with L < 64.
// Returns the /64 HCGA prefix.
func DeriveHCGAPrefix(aggregate netip.Prefix, prefixModifier [16]byte, pub *ecdsa.PublicKey) (netip.Prefix, error) {
    L := aggregate.Bits()
    if L >= 64 {
        return netip.Prefix{}, errors.New("hcga: aggregate must be shorter than /64")
    }
    pubDER, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        return netip.Prefix{}, err
    }
    aggBytes := aggregate.Masked().Addr().As16()

    h := sha256.New()
    h.Write(aggBytes[:8])
    h.Write(prefixModifier[:])
    h.Write(pubDER)
    subnetHash := h.Sum(nil)

    var prefixBytes [16]byte
    copy(prefixBytes[:], aggBytes[:L/8])

    // Fill subnet bytes from hash
    if L%8 == 0 {
        for i := L / 8; i < 8; i++ {
            prefixBytes[i] = subnetHash[i-L/8]
        }
    } else {
        shift := uint(L % 8)
        mask := byte(0xFF) << (8 - shift)
        prefixBytes[L/8] = (aggBytes[L/8] & mask) | (subnetHash[0] >> shift)
        for i := L/8 + 1; i < 8; i++ {
            j := i - L/8 - 1
            prefixBytes[i] = (subnetHash[j] << (8 - shift)) | (subnetHash[j+1] >> shift)
        }
    }
    // Zero the IID portion (bits 64-127)
    for i := 8; i < 16; i++ {
        prefixBytes[i] = 0
    }

    addr, ok := netip.AddrFromSlice(prefixBytes[:])
    if !ok {
        return netip.Prefix{}, errors.New("hcga: failed to form prefix address")
    }
    return netip.PrefixFrom(addr.Unmap(), 64), nil
}
```

# Acknowledgements
{:numbered="false"}

The authors would like to thank Fern Siedel and Kapil Agrawal for valuable input.

---
