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
whose full 128-bit value is a deterministic function of a hardware-bound key,
an operator-controlled aggregate prefix, and an RFC 3972 modifier. This capability
provides agentic and workload network accountability in multi-tenant
environments such as Kubernetes clusters, where infrastructure-assigned
prefixes provide no per-instance cryptographic binding.

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
to application-layer workload identity mechanisms such as those developed in
the IETF WIMSE working group {{WIMSE-ARCH}}.

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
subnet prefix, public key (SPKI format).

**SPKI:** SubjectPublicKeyInfo, the DER-encoded format for a public key as
defined in RFC 5480 for ECDSA keys. This is the same format used by RFC 3972
and RFC 4982.

## 3. RFC 3972 Background

RFC 3972 §5 defines the CGA IID generation procedure:

```
IID = SHA-256(modifier[16] || 0x00^9 || prefix[8] || public_key_SPKI)[:8]
IID[0] &= 0xFC    # clear bits 6 and 7 (universal/local and individual/group)
```

where `prefix[8]` is the first 8 bytes of the /64 prefix (the network
address, not the host part).

Verification works in reverse: given `(address, modifier, public_key)`,
recompute the IID and compare it against `address[8:16]`. The prefix input
is taken from the address itself (bits 0–63).

RFC 4982 {{RFC4982}} extends CGA to support multiple hash algorithms via a
hash algorithm extension. HCGA uses SHA-256 with ECDSA P-256, consistent
with the RFC 4982 framework.

## 4. Problem Statement

### 4.1 Infrastructure-Assigned Prefixes Carry No Key Binding

In RFC 3972 deployments, the /64 prefix is external. Consider a Kubernetes
node with prefix `2001:db8:cafe:1::/64` assigned by the CNI plugin. All pods
on that node share the same /64. Each pod generates a CGA IID from its own
key and the shared prefix, producing unique addresses within the /64.

The mechanism works: each pod gets a unique, verifiable address within the
/64. The limitation is that the prefix itself is a network infrastructure
artifact — it identifies the node or node subnet, not the individual agent.
The prefix alone carries no cryptographic relationship to any particular
workload key.

### 4.2 Per-Agent /64 Routing

A network operator managing a large agentic deployments may want per-agent
routing policy: rate limiting, traffic engineering, QoS, monitoring. If each
agent has its own /64, those policies map directly to routing table entries.
Infrastructure-assigned prefixes require an external table to connect an
address to an agent; hardware-derived prefixes carry that mapping in the
address itself.

### 4.3 Multiple Addresses per Agent

CGA allows a host to derive multiple addresses from the same key with
different modifiers. In RFC 3972, all such addresses share the same /64.
In HCGA, the agent owns the /64 entirely — it may derive addresses with
any IID within its /64, enabling per-connection address pseudonymity while
retaining per-agent /64 accountability.

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
- Bits L to 63: `SHA-256(public_key)[0:64-L]` — hardware-derived subnet bits
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

## 6. Multiple HCGA Addresses per Agent

The HCGA prefix depends only on the public key, while the IID depends on
both the key and the modifier. An agent can therefore derive multiple valid
addresses within the same /64 by varying the modifier. This enables:

- Per-connection pseudonymity: each outbound connection uses a different
  IID (different modifier), making traffic correlation within the /64
  more difficult for passive observers.
- Connection-level accountability: the registry maps the HCGA prefix
  to the agent; the specific IID is per-connection context.

Multiple addresses per agent do not affect forensic accountability: any
address in the agent's /64 is attributable to the same hardware key via
the prefix verification step.

## 7. Interaction with RFC 3972 CGA Parameters

HCGA reuses the RFC 3972 CGA parameter structure (modifier, subnet prefix,
collision count, public key) directly, with one substitution:

- **modifier**: unchanged, per RFC 3972
- **subnet prefix**: set to `hcga_prefix` (the derived /64), not the
  aggregate — this allows RFC 3972-compliant verifiers to validate the IID
  given the /64, without knowledge of HCGA
- **collision count**: unchanged, per RFC 3972
- **public key**: unchanged, per RFC 3972

An RFC 3972-compliant verifier, given `(hcga_address, cga_params)`, will
correctly validate the IID with `hcga_prefix` as the subnet prefix. It
cannot verify that `hcga_prefix` is itself derived from the public key —
that check requires a verifier that implements this specification.

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

### 9.1 Subnet Bit Security

The subnet bits are derived by truncating a SHA-256 hash of the public key.
SHA-256 preimage resistance prevents an attacker from forging a valid HCGA
prefix for a given key, and collision resistance prevents constructing two
keys with the same subnet bits (within the birthday bound noted in §5.7).

The subnet bits expose partial information about the public key — specifically,
a truncated hash output — which is equivalent to what the RFC 3972 IID
already reveals. No additional key material is exposed.

### 9.2 Privacy Implications

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

### 9.3 IPR Status of RFC 3972

RFC 3972 carries IETF IPR disclosures (ipr/676, KAME). Any standards-track
work extending RFC 3972 must address these encumbrances. This document takes
no position on IPR; that determination belongs to the IETF Standards Process.

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
verification itself does not distinguish between tiers; attestation-strength
labeling is the registry's responsibility. The RATS architecture {{RFC9334}}
provides the framework for remote attestation evidence conveyance;
{{RATS-KEY-ATTEST}} addresses hardware key attestation for HSMs and TPMs.
For SPIFFE-chained deployments, {{TRANSITIVE-ATTEST}} addresses transitive
attestation across workload boundaries.

## 10. IANA Considerations

### 10.1 CGA Algorithm Identifier

RFC 4982 establishes a registry for hash algorithm identifiers used in CGA.
This document uses SHA-256 with ECDSA P-256 key material and requests
registration of this combination in that registry:

| Algorithm | Hash | Key Type | Reference |
|---|---|---|---|
| HCGA-SHA256-P256 | SHA-256 | ECDSA P-256 (RFC 5480) | This document |

### 10.2 CGA Parameters Extension

No new CGA Parameters extensions are required. This document passes
`hcga_prefix` as the `subnet_prefix` field in the existing CGA Parameters
structure.

---

--- back

# Appendix A: Example HCGA Derivation (ECDSA P-256, /48 Aggregate)

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


# Appendix B: Go Implementation Sketch

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

# Acknowledgements
{:numbered="false"}

The authors would like to thank Fern Siedel and Kapil Agrawal for valuable input.

---
