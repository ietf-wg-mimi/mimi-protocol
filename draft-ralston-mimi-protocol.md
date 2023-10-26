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
    role: editor

# These folks wrote much of the content, which has been aggregated into this
# doc:
#  -
#     fullname: Konrad Kohbrok
#     organization: Phoenix R&D
#     email: konrad.kohbrok@datashrine.de
#  -
#     fullname: Raphael Robert
#     organization: Phoenix R&D
#     email: ietf@raphaelrobert.com
#  -
#     fullname: Matthew Hodgson
#     organization: The Matrix.org Foundation C.I.C.
#     email: matthew@matrix.org

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

> **TODO**: Describe notion of consent, similar to "connection KeyPackages" in
> Section 6 of {{?I-D.robert-mimi-delivery-service}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms and definitions are inherited from {{!I-D.barnes-mimi-arch}}.

# Rooms and Events {#rooms-and-events}

Rooms, described by {{!I-D.barnes-mimi-arch}}, contain both state events and an
associated MLS group for encryption operations. State events are used to frame
information and operations which exist outside of the MLS group, such as the
user participation list, room policy, and other metadata.

Events are sent in context of a room, validated against the room's policy,
and ordered by the hub server. Each event additionally contains an *event type*
to differentiate its payload format from other events. A state event is an event
with a *state key*. The combination of the event type and state key form a tuple
to establish *current state*: the most recently sent state events with distinct
type and state key pairs.

> **TODO**: Describe where room state is persisted, if at all. With this document's
> transport, it's stored adjacent to the MLS group. See
> {{?I-D.robert-mimi-delivery-service}} for possible in-MLS persistence.

## Event Schema {#event-schema}

Events are validated against their TLS presentation language format
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

   // Additional fields may be present as dependent on event type.
   select (Event.type) {
      case "m.room.user":
         UserEvent content; // see later in doc
      // more cases as required by registry
   }
} Event;
~~~

Note an "event ID" is not specified on the object. Events are sent ephemerally
and bound to the underlying cryptographic group state rather than referenced by
a consistent identifier.

The "origin server" of an event is the server implied by the `sender` field.

Events are immutable once sent.

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
> ID" in ralston-mimi-signaling).

> **TODO**: Include fields for encryption information. Possibly ciphersuite and
> similar so a server can check to ensure it supports the MLS dialect?

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
This is accomplished using {{op-external-join}}.

### Welcome Flow {#join-welcome}

> **TODO**: Is this better phrased as an invite rather than join?

This flow is more similar to an invite ({{invites}}), though provides the
receiving user's clients with enough information to join without external
commit.

The inviting user's client first requests KeyPackages for all of the target
user's client through {{op-claim}}. The inviting client then uses the
KeyPackages to create Welcome MLS messages for the target user's clients.

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

> **TODO**: Is this Welcome flow correct, specifically the handling of Welcome
> MLS messages?

## Leaves/Kicks {#leaves}

Leaving a room can signal a user declining an invite, voluntarily leaving the
room, or being kicked (removed) from the room. When the sender and target of
an `m.room.user` ({{ev-mroomuser}}) leave event are different, the target user
is being kicked. Otherwise the event represents a voluntary leave or declined
invite (if the previous participation state was "invited").

Like with other participation/membership operations, a user's leave is initiated
by updating their participation state first. This is done by sending
({{op-send}}) the relevant `m.room.user` ({{ev-mroomuser}}) state event to the
hub, which validates it as follows:

* If the target and sender are the same, the user MUST be in the invited,
  joined, or knocking participation state.

* Otherwise:

  * The target user of the kick MUST be in the joined participation state.
  * The sender for a kick MUST be in the joined participation state.

> **TODO**: Include special case permissions constraints.

If the event is valid, it is fanned out ({{fanout}}) to all particpating
servers, plus the target user's server.

The next commit in the MLS group MUST remove *all* of the target user's clients.
If there are multiple users in the leave participation state, all of their
clients MUST be removed in the same commit. Other proposals MAY be committed
alongside the removals, however the commit MUST at a minimum remove the affected
clients.

> **TODO**: Describe how hub server generates proposals? Or do we just require
> some member in the group to do it? See also: Section 3.5 of
> {{?I-D.robert-mimi-delivery-service}}.

Prior to a voluntary `m.room.user` leave event, the sender SHOULD send proposals
to remove their own clients from the MLS group. Where possible, those clients
SHOULD commit their removal prior to updating their participation state as well.

Clients can propose to remove themselves from the MLS group at any time. The hub
server MUST allow commits at any time to honor those proposals. The hub server
MUST NOT allow a commit which contains an inline proposal to remove another
client, unless that client belongs to a user in the leave participation state.

## Bans {#bans}

Bans imply kick, and are operated the same way as {{leaves}}, though with the
`m.room.user` ({{ev-mroomuser}}) state event using a `ban` participation state.

An added exception on the validation is also applied to permit preemptive bans:
the target user is not required to be in the joined state to allow the
participation state change.

Unbans can be performed by transitioning a user from the banned participation
state to leave with {{leaves}}.

## Knocks {#knocks}

In this state, the sender of a knock is requesting an invite ({{invites}}) to
the room. They do not have access to the MLS group.

> **TODO**: Discuss if this participation state is desirable, and figure out
> details for how it works. It'd likely just be an `m.room.user` state event
> with no MLS interaction, like invites are.

## `m.room.user` {#ev-mroomuser}

**Event type**: `m.room.user`

**State key**: ID of target user.

**Additional event fields**:

~~~
struct {
   // The new participation state for the target user.
   ParticipationState state;

   // Optional human-readable reason for the change. Typically most
   // useful on bans and knocks.
   opaque [[reason]];
} UserEvent;
~~~

**Additional validation rules**:

* Rules described by {{invites}}, {{joins}}, {{leaves}}, {{bans}}, {{knocks}}.

> **TODO**: Include validation rules for permissions.

> **TODO**: Somehow link the event to a client identity? (or several clients)
> See also: Section 3.8 of {{?I-D.robert-mimi-delivery-service}}.

# Application Messages

Clients engage in messaging through use of a content format
({{?I-D.ietf-mimi-content}}) and MLS Application Messages. The resulting
`PrivateMessage` is carried in an `m.room.encrypted` ({{ev-mroomencrypted}})
event.

The client's server sends the event to the hub with {{op-send}}. If the client's
server is the room's hub server, it completes the events with the steps
described by {{op-send}} instead. The event is then fanned out ({{fanout}}) by
the hub to all participating servers in the room, including the sender's.

How the event goes from client to server, and server to client, is out of scope
for this document.

## `m.room.encrypted` {#ev-mroomencrypted}

**Event type**: `m.room.encrypted`

**State key**: Not present.

**Additional event fields**:

~~~
struct {
   // The PrivateMessage
   MLSMessage message;
} EncryptedEvent;
~~~

**Additional validation rules**:

* `message` MUST be an MLS PrivateMessage.

# Transport {#transport}

Servers communicate with each other over HTTP {{!RFC9110}}. Endpoints have the
protocol version embedded into the path for simplified routing between physical
servers.

## Authentication

All endpoints, with the exception of `.well-known` endpoints use the mutually
authenticated mode of TLS {{!RFC5246}}. This provides guarantees that each
server is speaking to an expected party.

> **TODO**: More information specific to how TLS should be used, i.e. mandate
best practices that make sense in a mutually authenticated scenario that
involves two WebPKI based certificates.

Individual events may transit between multiple servers. TLS provides
point-to-point security properties while {{event-auth}} provides event security
guarantees when transiting over multiple servers.

## Endpoint Discovery

A messaging provider that wants to query the endpoint of another messaging
provider first has to discover the fully qualified domain name it can use to
communicate with that provider. It does so by performing a GET request to
`https://example.org/.well-known/mimi/domain`. example.org could, for example,
answer by providing the domain `mimi.example.org` (assuming that this is where
it responds to the REST endpoints defined in {{rest-api}}).

The expected response format is simply a `text/plain` body containing the fully
qualified domain name.

~~~
GET https://example.org/.well-known/mimi/domain

Response
mimi.example.org
~~~

## REST Endpoints {#rest-api}

The following REST endpoints can be used to communicate with a MIMI server.

All operations rely on TLS-encoded structs and therefore requests and responses
SHOULD use a `Content-Type` of `application/octet-stream`.

### Send Event {#op-send}

Asks the server to send an event ({{event-schema}}). Events can take two shapes
over this endpoint, depending on whether a follower or hub server is doing the
sending.

When a follower server is sending an event, it MUST only be attempting to send
to the hub server for the room. Follower servers receiving an event from another
follower server MUST reject the request with a `400` HTTP status code. The hub
server MUST populate the `authEventIds` and `prevEventId` fields of the event,
validate the resulting event, then reply with a `200` HTTP status code and the
resulting event ID ({{reference-hash}}). The resulting event is then fanned out
{{fanout}} to relevant servers in the room.

The hub server MUST validate events according to {{event-auth}} and any event
type-specific validation rules. If the event is malformed in any way, or the
room is unknown, the server MUST respond with a `400` HTTP status code.

Follower servers SHOULD apply the same validation as hub servers upon receiving
a send request to identify potentially malicious hub servers.

Follower servers sending an event to the hub server will not include
`authEventIds` or `prevEventId` because they are populated by the hub server.
Hub servers MUST employ locking to ensure each event has exactly one child
implied by `prevEventId`. This locking mechanism MAY cause another request to be
rejected because the room state was mutated. For example, if the hub receives
a ban event in one request and a message from the to-be-banned user in another,
the message may be rejected if the ban is processed first. Hub servers SHOULD
process requests in the order they were received.

If an event is rejected during processing, the event MUST NOT be fanned out.

~~~
struct {
   // The resulting event ID that is about to be fanned out by the hub server.
   // Not included if the called server is a follower server.
   opaque [[eventId]];
} SendEndpointResponse;
~~~

~~~
POST /v1/send
Content-Type: application/octet-stream

Body
TLS-serialized Event (including additional fields, such as CreateEvent)

Response
TLS-serialized SendEndpointResponse
~~~

Servers SHOULD retry this request with exponential backoff (to a limit) if they
receive timeout/network errors.

#### Fanout {#fanout}

A hub server fans an event out by using the send endpoint described above on all
participating servers in the room. A server is considered "participating" if it
has at least one user in the joined participation state, described by
{{membership}}.

Additional servers MAY have the event sent to them if required by the steps
leading up to fanout.

### Check Invite Event {#op-check}

Used by the hub server to ensure a follower server can (and is willing to)
process an incoming invite. The called server MAY use this opportunity to ensure
the inviting user has general consent to invite the target user. For example,
ensuring the invite does not appear spammy in nature and if the inviter already
has a connection with the invitee.

If the server does not recognize the event format of the `m.room.create`
({{ev-mroomcreate}}) event, or does not understand the policy/encryption
configuration contained within, it MUST reject the request.

The request MAY be rejected with a `400` HTTP status code. If everything looks
OK to the server, it responds with a `200` HTTP status code.

~~~
struct {
   // The `m.room.user` invite event.
   UserEvent invite;

   // The `m.room.create` event for the room.
   CreateEvent roomCreate;
} CheckInviteRequest;
~~~

~~~
POST /v1/check-invite
Content-Type: application/octet-stream

Body
TLS-serialized CheckInviteRequest

Response
Any meaningful information. The pass/fail is identified by the HTTP response
status code, not the response body.
~~~

The hub server SHOULD consider a network error as a rejection. It is expected
that the original sender will attempt to re-send the invite once the server is
reachable again.

### Retrieve Event {#op-get-event}

> **TODO**: What specific APIs does a follower server need to operate? Some
> options include:
>
> * `GET /v1/event/:eventId`
> * `GET /v1/room/:roomId/state` (current room state events)
> * `GET /v1/room/:roomId/state/:eventType/:stateKey`
> * `GET /v1/event/:eventId/child`

### Retrieve KeyPackages {#op-claim}

Asks the server for KeyPackages belonging to a user's clients. Like with
{{op-check}}, if the requesting user does not have general consent to invite the
target user, the request is rejected.

To ensure requests do not fail while clients are offline or otherwise
unreachable, KeyPackages SHOULD be uploaded by the generating client to their
local server for later usage.

> **TODO**: Mark KeyPackages of last resort somehow.

This request is always sent to the hub server which then proxies the request
directly to the relevant follower server.

~~~
struct {
   // The user ID to retrieve KeyPackages for. This will download 1 KeyPackage
   // for each of the user's clients.
   opaque userId;

   // The user ID requesting the KeyPackages for `userId`.
   opaque requestingUserId;

   // The room (group) ID where the KeyPackages are valid for.
   opaque roomId;
} GetKeyPackagesRequest;

struct {
   // One KeyPackage for each of the requested user's clients.
   KeyPackage keyPackages<V>;
} GetKeyPackagesResponse;
~~~

> **TODO**: Do we need to sign or otherwise guarantee security on the
> `requestingUserId`? We do for invite events, so why not here?

~~~
POST /v1/key_packages
Content-Type: application/octet-stream

Body
TLS-serialized GetKeyPackagesRequest

Response
TLS-serialized GetKeyPackagesResponse
~~~

### External Group Join {#op-external-join}

When a client wishes to perform an external join to the MLS group, it may
require assistance from the hub server in order to be successful. This endpoint
is used by a follower server on a client's behalf to complete the external join.

The hub server is able to provide this service to the requester because it keeps
track of the information required to generate a GroupInfo object. The requester
is still required to supply a `Signature` and relevant GroupInfo extensions,
which are required to complete the GroupInfo object.

~~~
struct {
   Extension group_info_extensions<V>;
   opaque Signature<V>;
} PartialGroupInfo;

struct {
   MLSMessage commit;
   PartialGroupInfo partial_group_info;
} MLSGroupUpdate;
~~~

The MLSMessage MUST contain a PublicMessage which contains a commit with sender
type NewMemberCommit.

~~~
POST /v1/external_join
Content-Type: application/octet-stream

Body
TLS-serialized MLSGroupUpdate

Response
Any meaningful information. The pass/fail is identified by the HTTP response
status code, not the response body.
~~~

### Add, Remove, and Update MLS Group Clients {#op-mls-add}

As described by {{joins}}, users which are joined participants are able to add
their clients at any time to the MLS group. Clients which do not belong to a
joined user MUST be rejected from joining the group. Similarly, clients may
elect to leave the MLS group at any time, as per {{leaves}}.

~~~
struct {
   // MUST be a PublicMessage with a commit that only contains Add proposals
   // for a joined user's clients.
   //
   // MUST NOT change the sending client's credential.
   MLSGroupUpdate group_update;
   MLSMessage welcome_messages<V>;
} AddClientsRequest;

struct {
   // MUST NOT change the sending client's credential.
   MLSGroupUpdate group_update;
} RemoveClientsRequest;

struct {
   // MUST contain a PublicMessage which contains a commit with an UpdatePath,
   // but not other proposals by value.
   MLSGroupUpdate group_update;
} UpdateClientRequest;

enum {
   add,
   remove,
   update,
} MLSOperation;

struct {
   MLSOperation operation;

   select (GroupUpdateRequest.operation) {
      case add:
         AddClientsRequest request;
      case remove:
         RemoveClientsRequest request;
      case update:
         UpdateClientRequest request;
   }
} GroupUpdateRequest;
~~~

The group update contained within `RemoveClientsRequest` is additionally subject
to the requirements of {{leaves}}.

~~~
POST /v1/group_update
Content-Type: application/octet-stream

Body
TLS-serialized GroupUpdateRequest

Response
Any meaningful information. The pass/fail is identified by the HTTP response
status code, not the response body.
~~~

# Security Considerations

Overall, the user participation state leads any possible MLS group state to
ensure malicious clients are not able to easily get access to messages.

> **TODO**: Other security guarantees? Consensus may be required here.

# IANA Considerations

IANA has created the following registries:

* MIMI Event Types

## MIMI Event Types

An event type denotes the nature of a payload contained in an event, in the
context of the MIMI protocol. The event type is a string composed of substrings
separated by dots.

The first substring is "m", followed by the logical container being affected
(typically just "room"), then a number of descriptor strings.

Example: `m.room.create`

> **TODO**: Does IANA need any other information for legal event types?

--- back

# Acknowledgments
{:numbered="false"}

This document is the consolidation of the following documents:

* {{?I-D.kohbrok-mimi-transport}} forms the majority of {{transport}}.

* {{?I-D.robert-mimi-delivery-service}} describes details for {{membership}},
  subsections of {{rest-api}} (per transport draft), and
  considerations for {{ev-mroomencrypted}}.

* {{?I-D.ralston-mimi-signaling}} describes {{event-schema}},
  {{room-creation}}, details of {{membership}}, and subsections of {{rest-api}}.

Aspects of {{?I-D.ralston-mimi-policy}} are additionally taken into
consideration in this document through subsections of {{membership}}, but is
largely unincorporated and may require updates to match this document's
specifics.

{{!I-D.barnes-mimi-arch}} was additionally used throughout the writing
of this document.
