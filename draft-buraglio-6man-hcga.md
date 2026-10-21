---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-buraglio-6man-hcga.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
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
venue:
  group: 6man
  type: Working Group
  mail: ipv6@ietf.org
  arch: https://example.com/WG
  github: buraglio/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Your Name Here
    organization: Your Organization Here
    email: your.email@example.com

normative:

informative:

...

---

## Abstract

RFC 3972 defines Cryptographically Generated Addresses (CGA), in which the
Interface Identifier (IID) portion of an IPv6 address is derived from a
cryptographic public key. The /64 subnet prefix is provided externally by
network infrastructure and is not bound to the key. This document specifies
Hierarchical CGA (HCGA), an extension to RFC 3972 in which part of the upper
64 bits of the address — specifically the portion between the organizational
prefix and the /64 boundary — is derived from the same public key as the IID.
The result is an IPv6 address where the full 128-bit value is a deterministic
function of a single hardware-bound key, an operator-controlled aggregate
prefix, and an RFC 3972 modifier. HCGA is motivated by AI agent and workload
network accountability requirements in multi-tenant environments such as
Kubernetes clusters, where infrastructure-assigned prefixes do not provide
per-instance cryptographic binding.

---

## 1. Introduction

RFC 3972 [RFC3972] provides a mechanism to bind an IPv6 host's network
address to a public key by deriving the 64-bit Interface Identifier (IID)
from a cryptographic hash of the key. This binding enables Secure Neighbor
Discovery [RFC3971] and is used by ANCHOR [ANCHOR-PoC] as the primary
forensic accountability signal.

RFC 3972 takes the /64 prefix as a trusted external input — a given from
network infrastructure. For hosts with a single, stable interface on a
well-administered network, this is appropriate. For container and
virtualized workloads, the prefix is assigned by an orchestration layer
(CNI plugin, cloud provider, hypervisor) and carries no cryptographic
relationship to the workload's identity.

This matters for AI agent accountability in two ways:

1. **Multiple agents per prefix.** Thousands of AI agent instances may share
   a single /64 prefix (e.g., all pods on a node subnet). The IID provides
   per-instance binding within the prefix, but the prefix itself is a
   coarse-grained infrastructure artifact.

2. **Per-agent routing granularity.** Routing and monitoring infrastructure
   operates at prefix granularity. If each agent instance occupies its own
   cryptographically-identified /64, routing tables can carry per-agent
   network policy without per-agent configuration — the prefix encodes the
   identity.

HCGA extends RFC 3972 by deriving the lower bits of the /64 prefix (the
"subnet bits" between the organizational aggregate and the /64 boundary)
from the same public key as the IID. This produces a two-level cryptographic
hierarchy:

- The /64 subnet identifies the agent instance at the routing level.
- The IID provides the RFC 3972 address-level binding within that subnet.

The 128-bit address is then a deterministic, verifiable function of the
hardware key, the aggregate prefix (operator-controlled), and the RFC 3972
modifier.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [RFC2119].

**Aggregate Prefix (A):** An IPv6 prefix of length L (L < 64), operator-
controlled, announced via BGP. All HCGA-derived addresses are within A.
Typical length: /48.

**Subnet bits:** The bits from position L through position 63 inclusive
(0-indexed from the MSB). Bit count: 64 − L. For a /48 aggregate, the
subnet bits occupy positions 48–63, a 16-bit field.

**Pod prefix / HCGA prefix:** The /64 derived by appending the subnet bits
to the aggregate prefix.

**CGA params:** As defined in RFC 3972: modifier (128-bit random value),
subnet prefix, public key (SPKI format).

**SPKI:** SubjectPublicKeyInfo, the DER-encoded format for a public key as
defined in RFC 5480 for ECDSA keys. This is the same format used by RFC 3972
and RFC 4982.

---

## 3. RFC 3972 Background

RFC 3972 §5 defines the CGA IID generation procedure:

```
IID = SHA-256(modifier[16] || 0x00^9 || prefix[8] || public_key_SPKI)[:8]
IID[0] &= 0xFC    # clear bits 6 and 7 (universal/local and individual/group)
```

where `prefix[8]` is the first 8 bytes of the /64 prefix (the network
address, not the host part).

Verification: given `(address, modifier, public_key)`, recompute the IID
and compare against `address[8:16]`. The prefix is taken from the address
itself (bits 0–63).

RFC 4982 [RFC4982] extends CGA to support multiple hash algorithms via a
hash algorithm extension. HCGA uses SHA-256 with ECDSA P-256, consistent
with the RFC 4982 framework.

---

## 4. Problem Statement

### 4.1 Infrastructure-Assigned Prefixes Carry No Key Binding

In RFC 3972 deployments, the /64 prefix is external. Consider a Kubernetes
node with prefix `2001:db8:cafe:1::/64` assigned by the CNI plugin. All pods
on that node share the same /64. Each pod generates a CGA IID from its own
key and the shared prefix, producing unique addresses within the /64.

This is correct and functional. The limitation is that the /64 prefix is a
network infrastructure artifact — it identifies the node (or node subnet),
not the agent. From the prefix alone, no cryptographic relationship to any
particular workload key can be established.

### 4.2 Per-Agent /64 Routing

A network operator managing a large AI agent deployment may want to apply
routing policy at per-agent granularity: rate limiting, traffic engineering,
QoS, monitoring. If each agent occupies a distinct /64, these policies map
directly to routing table entries. Infrastructure assigned prefixes require
an external mapping table; hardware-derived prefixes carry the mapping in
the address itself.

### 4.3 Multiple Addresses per Agent

CGA allows a host to derive multiple addresses from the same key with
different modifiers. In RFC 3972, all such addresses share the same /64.
In HCGA, the agent owns the /64 entirely — it may derive addresses with
any IID within its /64, enabling per-connection address pseudonymity while
retaining per-agent /64 accountability.

---

## 5. HCGA Specification

### 5.1 Parameters

HCGA takes the following inputs:

- **public_key**: ECDSA P-256 public key (or other RFC 4982-compatible key type)
- **modifier**: 128-bit random value (as in RFC 3972; SHOULD be regenerated per §5.3)
- **aggregate**: IPv6 prefix of length L, where L < 64 (operator-controlled)
- **hash_alg**: SHA-256 (required for this profile; other algorithms per RFC 4982)

### 5.2 Subnet Bit Derivation

Let `n = 64 - L` be the number of subnet bits.

```
subnet_bytes_count = ⌈n / 8⌉
subnet_bits        = SHA-256(public_key_SPKI_DER)[:subnet_bytes_count]
```

For a /48 aggregate (n = 16, subnet_bytes_count = 2):
```
subnet_bits = SHA-256(public_key_SPKI_DER)[0:2]   # 16 bits
```

The subnet bits are the most significant `n` bits of the extracted bytes.
For byte-aligned cases (n divisible by 8), no masking is needed. For
non-byte-aligned cases, the excess low-order bits of the last byte MUST
be zeroed.

### 5.3 HCGA Prefix Construction

```
hcga_prefix_bits = aggregate_bits[0:L] || subnet_bits[0:n]
hcga_prefix      = IPv6 prefix of length 64 formed from hcga_prefix_bits
```

Equivalently, in Go notation:
```go
var prefixBytes [8]byte
copy(prefixBytes[:], aggregate.Addr().As16()[:L/8])
subnetHash := sha256.Sum256(publicKeySPKIDER)
// copy the subnet bits into the remaining bytes
for i := L / 8; i < 8; i++ {
    prefixBytes[i] = subnetHash[i - L/8]
}
// if L is not byte-aligned, mask the partial byte
if L%8 != 0 {
    mask := byte(0xFF) << (8 - L%8)
    aggByte := aggregate.Addr().As16()[L/8] & mask
    subByte  := subnetHash[0] & ^mask
    prefixBytes[L/8] = aggByte | subByte
}
```

### 5.4 IID Derivation

The IID is computed per RFC 3972 §5 using `hcga_prefix` as the prefix input:

```
IID = SHA-256(modifier[16] || 0x00^9 || hcga_prefix_bytes[8] || public_key_SPKI_DER)[:8]
IID[0] &= 0xFC
```

where `hcga_prefix_bytes[8]` is the 8-byte representation of the /64
network address (i.e., the first 8 bytes of a 128-bit address formed by
appending 64 zero bits to `hcga_prefix`).

This is identical to RFC 3972 §5 with `hcga_prefix` substituted for the
externally-provided prefix.

### 5.5 HCGA Address Construction

```
hcga_address = hcga_prefix :: IID
```

The resulting 128-bit address has:
- Bits 0 to L−1: operator-controlled aggregate prefix (fixed, BGP-announced)
- Bits L to 63: SHA-256(public_key)[0:64-L] — hardware-derived subnet bits
- Bits 64 to 127: RFC 3972 IID — hardware-derived, modifier-randomized

### 5.6 Verification Procedure

Given `(hcga_address, modifier, public_key)`:

1. **Aggregate check:** verify that bits 0 to L−1 of `hcga_address` match
   the operator's aggregate prefix. This is a routing-level check, performed
   before cryptographic verification.

2. **Subnet bit check:** compute `SHA-256(public_key_SPKI_DER)` and verify
   that bits L to 63 of `hcga_address` match bits 0 to (63-L) of the hash.

3. **IID check:** extract `hcga_prefix` from bits 0–63 of `hcga_address`.
   Recompute the IID per §5.4. Verify that bits 64–127 of `hcga_address`
   match the computed IID (after the 0xFC masking).

All three checks MUST pass for the address to be considered a valid HCGA
address. Failure of any check MUST be treated as a verification failure.

### 5.7 Modifier Handling

The modifier serves the same purpose as in RFC 3972: collision avoidance
when the SHA-256 IID derivation produces an address that is already in use.
An implementation MUST implement the RFC 3972 §5 collision detection
procedure, incrementing the modifier until no collision is detected.

For HCGA, collision detection applies to both the IID (within the /64) and
the /64 prefix itself (across agents within the aggregate). The probability
of a /64 prefix collision for n agents in a /48 aggregate is approximately
n²/(2 × 2^16) — approximately 0.7% for 1,000 agents (birthday bound). An
operator MUST monitor for prefix collisions and MUST NOT issue two HCGA
addresses with the same /64 prefix. The modifier does not affect the subnet
bits; prefix collision requires either a different aggregate or a different
key.

---

## 6. Multiple HCGA Addresses per Agent

Because the HCGA prefix is a function of the public key alone (independent
of the modifier), and the IID is a function of the key and the modifier, an
agent may derive multiple valid HCGA addresses within the same /64 by using
different modifiers. This enables:

- Per-connection pseudonymity: each outbound connection uses a different
  IID (different modifier), making traffic correlation within the /64
  more difficult for passive observers.
- Connection-level accountability: the registry maps the HCGA prefix
  to the agent; the specific IID is per-connection context.

Multiple addresses per agent do not affect forensic accountability: any
address in the agent's /64 is attributable to the same hardware key via
the prefix verification step.

---

## 7. Interaction with RFC 3972 CGA Parameters

HCGA is designed to be compatible with the RFC 3972 CGA parameter structure.
The CGA parameters structure (modifier, subnet prefix, collision count,
public key) maps to HCGA as follows:

- **modifier**: unchanged, per RFC 3972
- **subnet prefix**: set to `hcga_prefix` (the derived /64), not the
  aggregate — this allows RFC 3972-compliant verifiers to validate the IID
  given the /64, without knowledge of HCGA
- **collision count**: unchanged, per RFC 3972
- **public key**: unchanged, per RFC 3972

An RFC 3972-compliant verifier given `(hcga_address, cga_params)` will
correctly validate the IID using `hcga_prefix` as the subnet prefix.
The additional HCGA-specific property — that `hcga_prefix` is itself
derived from the public key — requires a verifier that implements this
document.

---

## 8. Routing Considerations

### 8.1 Aggregate Announcement

The aggregate prefix A MUST be announced via BGP (with RPKI ROA) by the
autonomous system operating the ANCHOR deployment. Per-/64 routes are NOT
announced externally — they are internal to the cluster or network segment.
External observers see only the aggregate advertisement, as with any
provider-independent prefix assignment.

### 8.2 Intra-Cluster Routing

Within a Kubernetes cluster or datacenter fabric, per-/64 routes for active
agents are installed by the CNI plugin (Calico, Cilium with BGP enabled).
The HCGA /64 for each agent is programmed as a host route to the pod's
network namespace.

### 8.3 RPKI Alignment

The aggregate ROA covers all HCGA addresses by containment. No per-/64 ROA
is needed or appropriate — RPKI operates at the prefix level of BGP
announcements, and per-/64 routes are not BGP-advertised externally.
The chain `ROA(aggregate) → ASN → aggregate → HCGA /64 → IID` is
verifiable without additional RPKI infrastructure.

---

## 9. Security Considerations

### 9.1 Subnet Bit Security

The subnet bits are derived by truncating a SHA-256 hash of the public key.
Given SHA-256 preimage resistance, an attacker cannot forge a valid HCGA
prefix for a given key. Collision resistance prevents an attacker from
constructing two keys with the same subnet bits (within the birthday bound
noted in §5.7).

The subnet bits reveal partial information about the public key (specifically,
truncated hash output). This is equivalent to the information revealed by
the RFC 3972 IID. No additional key exposure results.

### 9.2 Privacy Implications

HCGA addresses are more linkable than RFC 3972 CGA addresses in one
dimension: the /64 subnet is stable across IID rotations (modifier changes).
Any two HCGA addresses sharing the same /64 are attributable to the same
hardware key, even without accessing the IID verification. This is the
design intent for AI agent accountability; it may be inappropriate for
privacy-sensitive use cases. Operators MUST document and consider this
before deploying HCGA for traffic involving personal data.

Multiple HCGA addresses per agent (§6) provide IID-level pseudonymity but
not /64-level pseudonymity. The /64 is permanently linkable to the hardware
key.

### 9.3 IPR Status of RFC 3972

RFC 3972 carries IETF IPR disclosures (ipr/676, KAME). Any standards-track
work extending RFC 3972 must address these encumbrances. This document does
not resolve IPR issues; that determination belongs to the IETF Standards
Process.

### 9.4 Hardware Root of Trust Scope

The security properties of HCGA depend on the hardware root of trust used
for the underlying key pair:

- **Hardware TPM 2.0 (physical):** non-extractable private key; maximum
  binding strength
- **vTPM (VM-bound):** bounded by hypervisor isolation; attestation via TDX/SEV-SNP
- **SPIFFE SVID key pair:** software-generated, rotated; no direct hardware binding;
  chain via SPIRE tpm_devid node attestation
- **Software key (stub mode):** no hardware binding; development use only

Relying parties MUST inspect the `tier` field in the ANCHOR registry entry
to determine the attestation strength of a given HCGA address. HCGA
verification does not distinguish between these tiers; attestation-strength
labeling is a registry responsibility.

---

## 10. IANA Considerations

### 10.1 CGA Algorithm Identifier

RFC 4982 establishes a registry for hash algorithm identifiers used in CGA.
This document uses SHA-256 with ECDSA P-256 key material. Registration of
this combination in the RFC 4982 IANA registry is requested:

| Algorithm | Hash | Key Type | Reference |
|---|---|---|---|
| HCGA-SHA256-P256 | SHA-256 | ECDSA P-256 (RFC 5480) | This document |

### 10.2 CGA Parameters Extension

No new CGA Parameters extensions are required. The `hcga_prefix` is
provided as the `subnet_prefix` field in the standard CGA Parameters
structure.

---

## 11. References

### 11.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119, March 1997.
- [RFC3972] Aura, T., "Cryptographically Generated Addresses (CGA)", RFC 3972, March 2005.
- [RFC4982] Bagnulo, M. and J. Arkko, "Support for Multiple Hash Algorithms in Cryptographically Generated Addresses (CGAs)", RFC 4982, July 2007.
- [RFC5480] Turner, S. et al., "Elliptic Curve Cryptography Subject Public Key Information", RFC 5480, March 2009.

### 11.2 Informative References

- [RFC3971] Arkko, J. et al., "SEcure Neighbor Discovery (SEND)", RFC 3971, March 2005.
- [RFC6437] Amante, S. et al., "IPv6 Flow Label Specification", RFC 6437, November 2011.
- [RFC9334] Birkholz, H. et al., "Remote ATtestation procedureS (RATS) Architecture", RFC 9334, January 2023.
- [ANCHOR-PoC] Buraglio, N., "ANCHOR: Agent Network Cryptographic Hardware Origin Recording", GitHub, 2026. https://github.com/buraglio/anchor
- [SPIRE] SPIFFE Project, "SPIRE v1.15.1", https://github.com/spiffe/spire
- [KATA] Kata Containers Project, "Kata Containers v3", https://katacontainers.io
- [KEYLIME] Keylime Project, "Keylime v7.14.3", https://keylime.dev
- [WIMSE-ARCH] Salowey, J. et al., "WIMSE Architecture", draft-ietf-wimse-arch, Work in Progress.
- [TRANSITIVE-ATTEST] Mandyam, G. and Walker, J., "Transitive Attestation for Sovereign Workloads", draft-mw-wimse-transitive-attestation, Work in Progress.

---

## Appendix A: Example HCGA Derivation (ECDSA P-256, /48 Aggregate)

Given:
- aggregate: `2001:db8:cafe::/48`
- ECDSA P-256 key pair (generated fresh; public key in SPKI DER form, 91 bytes)
- modifier: `0000000000000000` (16 zero bytes; use random in production)

Step 1 — Subnet bits (16 bits for /48 → /64):
```
pubkey_hash = SHA-256(public_key_SPKI_DER)
subnet_bits = pubkey_hash[0:2]   # e.g., 0x3a7f
```

Step 2 — HCGA prefix:
```
hcga_prefix = 2001:0db8:cafe:3a7f::/64
```

Step 3 — IID:
```
hcga_prefix_bytes = 20 01 0d b8 ca fe 3a 7f
IID_full = SHA-256(modifier[16] || 0x00^9 || hcga_prefix_bytes[8] || pubkey_SPKI_DER)[:8]
IID_full[0] &= 0xFC
IID = e.g., c8:5e:8b:4d:e3:ce:e9:49
```

Step 4 — HCGA address:
```
2001:db8:cafe:3a7f:c85e:8b4d:e3ce:e949
```

Verification:
1. Aggregate check: `2001:db8:cafe:` → matches operator's /48 ✓
2. Subnet check: `SHA-256(pubkey)[0:2] = 0x3a7f` → matches bits 48–63 ✓
3. IID check: recompute → `c85e:8b4d:e3ce:e949` ✓

---

## Appendix B: Go Implementation Sketch

```go
// DeriveHCGAPrefix derives the /64 HCGA prefix from an aggregate and public key.
// aggregate must be a /L prefix with L < 64. Returns the /64 pod prefix.
func DeriveHCGAPrefix(aggregate netip.Prefix, pub *ecdsa.PublicKey) (netip.Prefix, error) {
    L := aggregate.Bits()
    if L >= 64 {
        return netip.Prefix{}, errors.New("hcga: aggregate must be shorter than /64")
    }
    pubDER, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        return netip.Prefix{}, err
    }
    subnetHash := sha256.Sum256(pubDER)

    aggBytes := aggregate.Addr().As16()
    var prefixBytes [16]byte
    copy(prefixBytes[:], aggBytes[:L/8])

    // Fill subnet bits from hash
    for i := L / 8; i < 8; i++ {
        prefixBytes[i] = subnetHash[i-L/8]
    }
    // Handle non-byte-aligned aggregate boundary
    if L%8 != 0 {
        mask := byte(0xFF) << (8 - L%8)
        prefixBytes[L/8] = (aggBytes[L/8] & mask) | (subnetHash[0] & ^mask)
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
