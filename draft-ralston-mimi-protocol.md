---
title: "MIMI Protocol"
abbrev: "MIMI Protocol"
category: std

docname: draft-ralston-mimi-protocol-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "More Instant Messaging Interoperability"
keyword:
 - mimi
 - messaging
 - interoperability
 - protocol
 - chat
 - implementation
venue:
  group: "More Instant Messaging Interoperability"
  type: "Working Group"
  mail: "mimi@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mimi/"
  github: "turt2live/ietf-mimi-protocol"
  latest: "https://turt2live.github.io/ietf-mimi-protocol/draft-ralston-mimi-protocol.html"

author:
 -
    fullname: Travis Ralston
    organization: The Matrix.org Foundation C.I.C.
    email: travisr@matrix.org
 -
    fullname: Rohan Mahy
    organization: Wire
    email: rohan.mahy@wire.com

normative:

informative:


--- abstract

This document describes the transport and messaging protocols required
for interoperable instant messaging using MLS {{!RFC9420}}, as defined
by {{!I-D.barnes-mimi-arch}}.

--- middle

# Introduction

**TODO**: Introduction

# Rooms

Described by {{!I-D.barnes-mimi-arch}}, rooms have state which track the policy,
user participation list, and other metadata. The room additionally contains an
MLS group for actual conversation flows.

Everything in a room is described as a signaling event. Room state information
is transmitted as a "state event". Each event contains exactly 1 datum.

**TODO**: Talk about history, event chaining, etc.

**TODO**: Talk about event format.

**TODO**: Talk about where rooms are persisted.

# TODO: Scenario content

Incorporate scenario flows.

Alice adds Bob:

1. Alice creates room.
2. Alice signals invite for Bob.
3. Hub server (Alice's) contacts Bob's server and sends invite.
4. Bob's server checks that it is capable of participating.
5. Bob's clients receive invite.
6. Later: Bob's client accepts invite by sending a join signaling event through
   the hub to all other participants.
7. Bob's client retrieves GroupInfo.
8. Bob creates and sends an external commit through the hub.

Alice adds Bob (alternative):

1. Alice creates room.
2. Alice discovers all of Bob's clients.
3. Alice prepares Welcome messages, attaches them to a signaling join event for
   Bob.
4. That package is sent via the hub to Bob's server.
5. Bob's server verifies it is capable of participating.
6. Bob's server acks the request as OK, informs Bob that they're now joined and
   delivers accompanying Welcome messages.
7. Concurrent to the ack, hub fans out the join.
8. Bob is now both a participant and a member.

Alice leaves:

1. Alice proposes self-eviction via remove proposals.
2. Alice leaves via signaling event.
3. Hub requires Alice's proposals to be committed next.

Alice leaves (alternative):

1. Alice leaves via signaling event.
2. Hub (or any other member) generates remove proposals for Alice.
3. Hub requires those proposals to be committed next.

# Participation

**TODO**:

* In general case, signaling leads encryption
* Skip policy and consent for now

# Membership

**TODO**:

* MLS

# Transport

**TODO**: This section. Or do we imply it throughout?

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Security Considerations

**TODO**: Probably more words. (or imply throughout)

# IANA Considerations

This document has no IANA actions.

**TODO**: This needs content.

--- back

# Acknowledgments
{:numbered="false"}

This document is the consolidation of the following documents:

* {{?I-D.robert-mimi-delivery-service}}
* {{?I-D.ralston-mimi-signaling}}
* {{?I-D.ralston-mimi-policy}}
* {{?I-D.kohbrok-mimi-transport}}
