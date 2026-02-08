---
title: CausalGuard Behavioral Specification
abbrev: CausalGuard
docname: draft-causalguard-behavioral-00
date: 2026-02-08
category: std

ipr: trust200902
area: Security
workgroup: MLS
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Developer
    name: Antigravity Developer
    organization: CausalGuard
    email: dev@causalguard.io

normative:
  RFC2119:

--- abstract

This document specifies the behavioral requirements for CausalGuard, a post-quantum threshold signature scheme for securing causal interactions in distributed systems. It defines the protocol flow, message formats, and security invariants required for compliant implementations.

--- middle

# Introduction

CausalGuard provides a mechanism for aggregating independent post-quantum signatures into a succinct Zero-Knowledge Proof (ZK-SNARK), enabling scalable verification of causal chains across disparate networks.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Protocol Overview

The protocol consists of three phases: Setup, Signing, and Aggregation.

## Setup Phase

Validators generate independent keypairs $(pk_i, sk_i)$ and commit to a global Merkle Root $R$.

## Signing Phase

Validators sign a message $M$ using $sk_i$, producing a signature $\sigma_i$.

## Aggregation Phase

An aggregator collects $t$ valid signatures and produces a recursive proof $\pi$ attesting to the validity of the threshold signature.

# Security Considerations

Implementations MUST ensure:
1.  Private keys are zeroized immediately after use.
2.  All cryptographic operations are constant-time.
3.  The aggregation proof $\pi$ is zero-knowledge with respect to the individual signers.

# IANA Considerations

This document has no IANA actions.

--- back
