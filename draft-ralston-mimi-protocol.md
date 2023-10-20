---
title: "More Instant Messaging Interoperability (MIMI) using HTTPS and MLS"
abbrev: "MIMI+MLS Protocol"
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
 - interoperable messaging
 - chat
 - secure messaging
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
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad.kohbrok@datashrine.de
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com
 -
    fullname: Matthew Hodgson
    organization: The Matrix.org Foundation C.I.C.
    email: matthew@matrix.org

normative:

informative:
   RFC8446:


--- abstract

The More Instant Messaging Interoperability (MIMI) working group is chartered to
use Messaging Layer Security (MLS) {{!RFC9420}} for its encryption/security
layers. This document implements the architecture described by {{!I-D.barnes-mimi-arch}},
detailing the components required to achieve MLS-secured messaging
interoperability.

--- middle

# Introduction

The More Instant Messaging Interoperability (MIMI) working group is responsible
for specifying the set of protocols required to achieve secure, modern,
messaging interoperability using MLS {{!RFC9420}}. {{!I-D.barnes-mimi-arch}}
outlines an overall architecture for interoperable communications, and this
document implements those components using MLS and HTTP for the security and
specific transport details.

Each MIMI room uses state events to track user-level participation and
interaction with the room, and an accompanied MLS group for client-level
membership and messaging. The MLS group's membership consists of the clients
which belong to the participating users in the MIMI room.

MLS describes an abstract concept of a "Delivery Service" (DS) that is
specifically responsible for ordering handshake messages and more generally
delivering messages to the intended recipients. Collectively, all of the servers
in a MIMI room fulfill the Delivery Service role, with the hub server performing
the ordering of handshake messages. The hub server is additionally responsible
for tracking details about the room to assist clients in joining, validating
events and handshake messages, and enforcing the required policy against the
room and MLS group states.

Servers communicate with each other using a mutually authenticated mode of TLS
{{!RFC5246}} over HTTP {{!RFC9110}}. This document does not describe a protocol
for clients to communicate with a server. Instead, clients use provider-specific
APIs to accomplish "last mile" delivery of events and messages.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms and definitions are inherited from {{!I-D.barnes-mimi-arch}}.

# Rooms and Events {#rooms-and-events}

Rooms, described by {{!I-D.barnes-mimi-arch}}, contain both state events and an
associated MLS group for encryption operations. State events are used to frame
information and operations which exist outside of the MLS group, such as the
user participation list, room policy, and other metadata.

Events are sent in context of a room, authenticated against the room's policy,
and ordered by the hub server. Each event additionally contains an *event type*
to differentiate its payload format from other events. A state event is an event
with a *state key*. The combination of the event type and state key form a tuple
to establish *current state*: the most recently sent state events with distinct
type and state key pairs.

The hub server MUST persist at least the current room state, and MAY discard
user participation events for users who are in the `leave` state. The hub server
SHOULD persist all other events for the benefit of other servers in the room.

> **TODO**: Check that this history requirement matches agreed semantics.

## Event Schema {#event-schema}

Events are authenticated against their TLS presentation language format
({{Section 3 of RFC8446}}):

~~~
// See the "MIMI Event Types" IANA registry for values.
// Example: "m.room.create"
opaque EventType;

struct {
   // The room where the event is sent to.
   opaque roomId;

   // The event type.
   EventType type;

   // If present, the event is a state event.
   opaque [[stateKey]];

   // Who or what sent this event.
   opaque sender;

   // The origin server's content hash of the event.
   // See the "Content Hashes" section for information.
   uint8 contentHash[32];

   // The origin server's signature over the event.
   // See the "Signatures" section for information.
   opaque signature<V>;

   // The event IDs which authorize this event to be sent in the room,
   // as defined by the policy.
   // See the "[Event] Authentication" section for information.
   opaque authEventIds[];

   // The event ID of the parent event. This will be an empty string if
   // the `type` is `m.room.create`.
   opaque prevEventId;

   // Additional fields may be present as dependent on event type.
} Event;
~~~

Note an "event ID" is not specified on the object. The event ID for an event is
the sigil `$` followed by the URL-Safe Unpadded Base64-encoded reference hash
({{reference-hash}}) of the event.

The "origin server" of an event is the server implied by the `sender` field.

Events are immutable once sent, but may be redacted ({{event-auth}}) to remove
non-critical information.

## Authentication {#event-auth}

Events simultaneously carry information which is critical for the protocol to
operate, and other information which is less essential. The less essential
information is often user-supplied, and ideally can be removed without
"breaking" the room. MIMI supports removing non-critical information from events
through *redaction*.

Redaction creates a consistent representation of an event suitable for signing.
It is not an approach for "deleting" an event. Deletions are instead handled by
the content format for application messages in MIMI.

There are two scenarios where a redaction is applied:

1. When a mismatched content hash ({{content-hash}}) for an event is received.
2. When an `m.room.redaction` ({{ev-mroomredaction}}) message event is received,
   targeting an event.

When applying a redaction, all fields described by {{event-schema}} MUST NOT be
removed. Individual event types MAY describe additional fields to retain. All
other fields MUST be removed.

Events are authenticated against their redacted form. If an event fails
authentication, it is *rejected*. Rejected events are dropped and not forwarded
any further. For example, a hub rejecting an event would not send it to follower
servers. A follower server rejecting an event sent by a hub would not forward it
to local clients.

The redacted event is signed ({{event-signing}}) to verify that the event was
sent by the referenced originating server. If the signature verification fails,
the event is rejected.

Each event references a set of "auth events" which permit the event to be sent.
This field is populated by the hub server upon receipt of a partial event to
send. The specific event types required to be referenced in this field are
described by the room policy, but are typically the `m.room.create` ({{ev-mroomcreate}}),
and `m.room.user` ({{ev-mroomuser}}) state events at a minimum. If an event is
missing a required auth event, or contains a reference to an unknown/rejected
event, the event is rejected.

If the event's content hash does not match the calculated content hash, the
event is redacted before being sent any further. Note that if an event is
already manually redacted with a redaction event, it will in most cases fail a
content hash check.

Individual event types MAY specify additional authentication requirements, such
as field validation or ordering requirements.

### Reference Hash {#reference-hash}

Events are referenced by ID in relation to each other, forming the room history
and auth chain. If the event ID was a sender-generated value, any server along
the send or receive path could "replace" that event with another perfectly legal
event, both using the same ID.

By using a calculated value, namely the reference hash, if a server does try to
replace the event then it would result in a completely different event ID. That
event ID becomes impossible to reference as it wouldn't be part of the proper
room history.

An event's reference hash is calculated by redacting it, removing the
`signature` field if present, then serializing the resulting object. The
serialized binary is then hashed using SHA256 {{!RFC6234}}.

To further create an event ID, the resulting hash is encoded using URL-Safe
Unpadded Base64 and prefixed with the `$` sigil.

> **TODO**: Reference "URL-Safe Unpadded Base64" specification.

### Content Hash {#content-hash}

An event's content hash prevents servers from modifying details of the event not
covered by the reference hash itself. For example, a room name state event
doesn't have the name itself covered by a reference hash because it's redacted,
so it's instead covered by the content hash, which is in turn covered by the
reference hash. This allows the event to later be redacted without affecting the
event ID of that event.

To calculate a content hash, the following fields are removed from the event
first:

* `contentHash`
* `signature`
* `authEventIds`
* `prevEventId`

`authEventIds` and `prevEventId` are removed because they are populated by the
hub server. The content hash is to preserve the origin server's event, not the
hub server's.

The resulting object is then serialized and hashed using SHA256 {{!RFC6234}}.

Note that the event is *not* redacted in the calculation of a content hash. This
is to ensure that *all* origin-provided fields are protected by a hash and
trigger redaction if a field changed along the send path.

The content hash is additionally covered by the reference hash and event
signature.

### Signatures {#event-signing}

An event's content hash covers the unredacted contents, and it's reference hash
covers the redacted event contents (including the content hash). The hashes
alone are not authenticated and require an additional verification mechanism.
Signatures provide the needed authentication mechanism, and are applied by the
event's origin server.

Signatures are computed by first redacting the event, then removing the
`signature`, `authEventIds`, and `prevEventId` fields if present. The resulting
object is then serialized and signed using the server's key.

> **TODO**: Use mTLS keys? Source drafts use Ed25519 keys, but then we need to
> distribute keys all over the place.

Like content hashes ({{content-hash}}), `authEventIds` and `prevEventId` are
removed from the event because they are populated by the hub server.

## Creation {#room-creation}

Rooms (and therefore MLS groups) are first created within the provider, out of
scope from MIMI. When the room is exposed to another server over the MIMI
protocol, such as with an explicit invite to another user, the creating server
MUST produce the following details:

* An `m.room.create` ({{ev-mroomcreate}}) state event describing the encryption
  and policy details for the room.
* A universally unique room ID (represented by the create event).
* An `m.room.user` ({{ev-mroomuser}}) state event which points to the create
  event as a parent for the create event's `sender`.
* An MLS group with a group ID matching the room ID, and contains a device
  belonging to the create event's `sender`.

This is the minimum state required by a MIMI room. Room creators MAY wish to
include additional details in the initial state, such as configuration of the
room's policy, adding the creator's other clients to the MLS group state, etc.

### `m.room.create` {#ev-mroomcreate}

**Event type**: `m.room.create`

**State key**: Zero byte length string.

**Additional event fields**:

~~~
struct {
   // TODO
} CreateEvent;
~~~

> **TODO**: Include fields for policy information (previously called a "policy
> ID" in ralston-mimi-signaling). Protect this new field from redaction.

> **TODO**: Include fields for encryption information. Possibly ciphersuite and
> similar so a server can check to ensure it supports the MLS dialect? Protect
> this new field from redaction.

**Additional authentication rules**:

* The event's `prevEventId` MUST be a zero byte length string.
* The event's `authEventIds` MUST be empty.
* The event MUST be the first event in the room.

# User Participation and Client Membership {#membership}

In a MIMI room, users are *participants* with an associated
*participation state* whereas clients of those users are *members* of the MLS
group. In most scenarios, the user's participation state is updated first or
simultaneously with the MLS group membership to enforce membership more easily.

Users will always exist in one of the following participation states:

~~~
enum {
   invite,  // "Invited" state.
   join,    // "Joined" state.
   leave,   // "Left" state (including Kicked).
   ban,     // "Banned" state.
   knock,   // "Knocking" state.
   (65535)
} ParticipationState;
~~~

These states allow a user to remain logically "joined" to the conversation when
they have zero MLS-capable clients available. The user will not be able to see
messages sent while they had no clients, but can perform an external join at any
time to get back into the MLS group. A user with zero clients in the MLS group
is considered to be an *inactive participant*. Users with one or more clients
in the MLS group are *active participants*.

All servers with at least one user of theirs in the "joined" participation state
are considered to be "in" or "participating" in the room. By default, all events
sent to a room are distrubuted by the hub to participating servers. This is
discussed further in {{fanout}}.

## Invites {#invites}

An *invite* is when a user (or more specifically, a user's client) is attempting
to introduce *all* of another user's clients to the room and MLS group. This is
first done by updating the target user's participation state through the hub
server for the room.

Updating the target user's participation state is done using the following
steps, and is visualized in {{fig-invites}}.

1. The inviter's server generates an `m.room.user` ({{ev-mroomuser}}) state
   event to invite the target user. Typically this begins with a
   client-initiated request to the server using the provider-specific API.

2. The inviter's server sends ({{op-send}}) the `m.room.user` event to the hub
   server. If the inviter's server is the hub server, it does the steps
   described in {{op-send}} to complete the event.

3. The hub server validates the event to ensure the following:

   * The target user of the invite MUST NOT already be in the banned or joined
     states.

   * The sender of the invite MUST already be in the joined state.

4. If the event is invalid, it is rejected. Otherwise, it is forwarded by the
   hub to the target user's server to give it the opportunity to reject the
   invite early in the process. This is described by {{op-check}}.

5. If the target server rejected the event, the event is rejected by the hub as
   well. Otherwise, the event is fanned out ({{fanout}}) to all participating
   servers, plus the target server if not already participating.

At this stage, the *user* is now invited but their clients are not members of
the MLS group. The invite is delivered to the target's clients through relevant
provider-specific API where the user can then accept or decline the invite.

If the user declines the invite, they are transitioned to the leave state
described by {{leaves}}. Accepting is done by joining ({{joins}}) the room.

~~~ aasvg
+---+                            +-----+                         +---+
| A |                            | Hub |                         | B |
+---+                            +-----+                         +---+
  |                                 |                              |
  | Create m.room.user invite       |                              |
  |-------------------------+       |                              |
  |                         |       |                              |
  |<------------------------+       |                              |
  |                                 |                              |
  | Send event request initiated    |                              |
  |-------------------------------->|                              |
  |                                 |                              |
  |                                 | Validate m.room.user event   |
  |                                 |--------------------------+   |
  |                                 |                          |   |
  |                                 |<-------------------------+   |
  |                                 |                              |
  |    200 OK to send event request |                              |
  |<--------------------------------|                              |
  |                                 |                              |
  |                                 | Check event request          |
  |                                 |----------------------------->|
  |                                 |                              |
  |                                 |                       200 OK |
  |                                 |<-----------------------------|
  |                                 |                              |
  |           Async fanout of event | Async fanout of event        |
  |<--------------------------------|----------------------------->|
  |                                 |                              |
~~~
{: #fig-invites title="Invite happy path" }

## Joins {#joins}

A user can join a room in two ways:

1. Using an external commit to Add themselves to the MLS group.
2. Receiving a Welcome message from a joined member of the MLS group.

In both cases, a join `m.room.user` ({{ev-mroomuser}}) state event is also sent.

Typically, a client will use the first option when joining a public room or
responding to an invite because the hub server can assist them in the join.
Option 2 is generally used as a form of invite, though skipping the explicit
`m.room.user` invite described by {{invites}}.

The hub server MUST allow proposals and commits to add a user's own clients if
they're in the joined participation state. Similarly, the hub server MUST NOT
allow proposals or commits to add clients which are not in the joined
participation state. These conditions permit the user to add their own clients
after joining without issue, which may involve an external commit.

### External Commit Flow {#join-external}

The joining user's server first updates the user's participation state (an
`m.room.user` state event, {{ev-mroomuser}}) and sends that to the hub
({{op-send}}) for validation. If the joining user's server is the hub server, it
does the steps described in {{op-send}} to complete the event.

The join event is then validated by the hub as follows:

* The target and sending user of the event MUST be the same.
* The target user MUST NOT be banned from the room.

> **TODO**: Does requiring the sender and state key to be the same prohibit
> the Welcome flow from working? (I don't believe so because they still need
> to Add themselves?)

> **TODO**: Incorporate public and invite-only room conditions from policy.

If the event is valid, it is fanned out ({{fanout}}) to all participating
servers in the room, which now includes the joining server (if not already).

> **TODO**: It would be helpful if in response to the send request the hub
> server provided information required to externally join, maybe.

The user's clients are then able to use external commits to join the MLS group.
This is accomplished using {{op-external-commit-info}}.

### Welcome Flow

> **TODO**: Is this better phrased as an invite rather than join?

This flow is more similar to an invite ({{invites}}), though provides the
receiving user's clients with enough information to join without external
commit.

The inviting user's client first requests Key Packages for all of the target
user's client through {{op-claim}}. The inviting client then uses the Key
Packages to create Welcome MLS messages for the target user's clients.

The Welcome messages are sent to the hub server alongside an `m.room.user`
({{ev-mroomuser}}) invite event using {{op-send}}. If the inviting user's server
is the hub server for the room, it completes the event using the steps described
by {{op-send}} instead. The event is validated according to {{invites}} and
fanned out ({{fanout}}) to all participating servers, plus the target user's
server. The target user's server also receives the Welcome messages to deliver
to the relevant clients.

The user can then join the room by sending an `m.room.user` join event. The
process and applied validation are the same as {{join-external}}. The user's
clients can then Add themselves to the MLS group using the Welcome messages they
received earlier. If the Welcome messages are no longer valid, the clients can
use external commits instead.

> **TODO**: Should we permit the join event to be accompanied by the client's
> Add commits?

## Leaves/Kicks {#leaves}

## Bans {#bans}

## Knocks {#knocks}

In this state, the sender of a knock is requesting an invite ({{invites}}) to
the room. They do not have access to the MLS group.

> **TODO**: Discuss if this participation state is desirable, and figure out
> details for how it works. It'd likely just be an `m.room.user` state event
> with no MLS interaction, like invites are.

# TODO: Sections

*These headers exist as placeholder anchors.*

> **TODO**: This placeholder section should be removed before first publish.

## `m.room.redaction` {#ev-mroomredaction}

## `m.room.user` {#ev-mroomuser}

## Fanout {#fanout}

*Reference {{membership}}*.

## Operation: Send Event {#op-send}

*Reference "complete fields on event and resume further processing before {{fanout}}"*.

## Operation: Check Event {#op-check}

*Ensure supports policy, encryption, and has consent*.

## Operation: Information for External Commit {#op-external-commit-info}

## Operation: Claim Key Packages {#op-claim}

# TODO: Scenario content

> **TODO**: This placeholder section should be removed before first publish.

> **TODO**: Incorporate these scenario flows.

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

# Security Considerations

> **TODO**: Populate this section.

# IANA Considerations

This document has no IANA actions.

> **TODO**: Populate this section.

--- back

# Acknowledgments
{:numbered="false"}

This document is the consolidation of the following documents:

* {{?I-D.robert-mimi-delivery-service}}
* {{?I-D.ralston-mimi-signaling}}
* {{?I-D.kohbrok-mimi-transport}}

Aspects of {{?I-D.ralston-mimi-policy}} are additionally taken into
consideration in this document, but is largely unincorporated and may require
updates to match this document's specifics.
