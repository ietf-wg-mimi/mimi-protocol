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
  github: "bifurcation/ietf-mimi-protocol"
  latest: "https://bifurcation.github.io/ietf-mimi-protocol/draft-ralston-mimi-protocol.html"

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

contributor:
- name: Rohan Mahy
  org: Wire
  email: rohan.mahy@wire.com

normative:

informative:

--- abstract

This document specifies the More Instant Messaging Interoperability (MIMI)
transport protocol, which allows users of different messaging providers to
interoperate in group chats (rooms), including to send and receive messages,
share room policy, and add participants to and remove participants from rooms.
MIMI describes messages between providers, leaving most aspects of the
provider-internal client-server communication up to the provider.  MIMI
integrates the Messaging Layer Security (MLS) protocol to provide end-to-end security
assurances, including authentication of protocol participants, confidentiality
of messages exchanged within a room, and agreement on the state of the room.

--- middle

# Introduction

The More Instant Messaging Interoperability (MIMI) transport protocol enables providers of
end-to-end encrypted instant messaging to interoperate. As described in the MIMI
architecture {{?I-D.barnes-mimi-arch}}, group chats and direct messages are
described in terms of "rooms".  Each MIMI protocol room is hosted at a single
provider (the "hub" provider"), but allows users from different providers to
become participants in the room. The hub provider is responsible for ordering
and distributing messages, enforcing policy, and authorizing messages. It also
keeps a copy of the room state, which includes the room policy and participant
list, which it can provide to new joiners. Each provider also
stores initial keying material for its own users (who may be offline).

This document describes the communication among different providers necessary to
support messaging application functionality, for example:

* Sharing room policy
* Adding and removing participants in a room
* Exchanging secure messages

In support of these functions, the protocol also has primitives to fetch initial
keying material and fetch the current state of the underlying end-to-end encryption
protocol for the room.

Messages sent inside each room are end-to-end encrypted using the Messaging
Layer Security (MLS) protocol {{!RFC9420}}, and each room is associated with an
MLS group. MLS also ensures that clients in a room agree on the room policy and
participation.  MLS is integrated into MIMI in such a way as to ensure that a
client is joined to a room's MLS group only if the client's user is a
participant in the room, and that all clients in the group agree on the state
of the room (including, for example, the room's participant list).

## Known Gaps

In this version of the document, we have tried to capture enough concrete
functionality to enable basic application functionality, while defining enough
of a protocol framework to indicate how to add other necessary functionality.  The
following functions are likely to be needed by the complete protocol, but are
not covered here:

Authorization policy:
: In this document, we assume that all participants in a room have equal
capability.  Actual messaging systems have authorization policies for which
clients can take which actions in a room.

Advanced join/leave flows:
: In this document, all adds / removes / joins / leaves are initiated from
within the group, since this aligns well with MLS.  Messaging application
support a variety of other flows, some of which this protocol will need to
support.

Consent:
: In this document, we assume that any required consent has already been
obtained, e.g., a user consenting to be added to a room by another user.  The
full protocol will need some mechanisms for establishing this consent.

Identifiers:
: Certain entities in the MIMI system need to be identified in the protocol.  In
this document, we define a notional syntax for identifiers, but a more
concrete one should be defined.

Abuse reporting:
: There is no mechanism in this document for reporting abusive behavior to a
messaging provider.

Identifier resolution:
: In some cases, the identifier used to initiate communications with a user
might be different from the identifier that should be used internally.  For
example, a user-visible handle might need to be mapped to a durable internal
identifier.  This document provides no mechanism for such resolution.

Authentication
: While MLS provides basic message authentication, users should also be able
to (cryptographically) tie the identity of other users to their respective
providers. Further authentication such as tying clients to their users (or the
user's other clients) may also be desirable.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms and definitions are inherited from {{!I-D.barnes-mimi-arch}}.  We also
make use of terms from the MLS protocol {{!RFC9420}}.

Throughout this document, the examples use the TLS Presentation Language
{{!RFC8446}} and the semantics of HTTP {{!RFC7231}} respectively as
placeholder a set of binary encoding mechanism and transport semantics.

The protocol layering of the MIMI transport protocol is as follows:

1. An application layer that enables messaging functionality
2. A security layer that provides end-to-end security guarantees:
    * Confidentiality for messages
    * Authentication of actors making changes to rooms
    * Agreement on room state across the clients involved in a room
3. A transport layer that provides secure delivery of protocol objects between
   servers.

~~~ aasvg
+------------------------+
|       Application      |
|       +----------------+
|       |  E2E Security  |
+-------+----------------+
|        Transport       |
+------------------------+
~~~
{: #fig-layers title="MIMI protocol layering" }

MIMI uses MLS {{!RFC9420}} for end-to-end security, using the MLS AppSync
proposal type to efficiently synchronize room state across the clients involved
in a room. The MIMI transport is based on HTTPS over mutually-authenticated
TLS.

# Example protocol flow

This section walks through a basic scenario that illustrates how a room works
in the MIMI protocol.  The scenario involves the following actors:

* Service providers `a.example`, `b.example`, and `c.example` represented by
  servers `ServerA`, `ServerB`, and `ServerC` respectively
* Users Alice (`alice@a.example`), Bob (`bob@b.example`) and Cathy
  (`cathy@c.example`) of the respective service providers
* Clients `ClientA1`, `ClientA2`, `ClientB1`, etc. belonging to these users
* A room `clubhouse@a.example` where the three users interact

As noted in {{!I-D.mimi-arch}}, the MIMI protocol only defines interactions
between service providers' servers.  Interactions between clients and servers
within a service provider domain are shown here for completeness, but
surrounded by `[[ double brackets ]]`.

## Alice Creates a Room

The first step in the lifetime of a MIMI room is its creation on the hub server.
This operation is local to the service provider, and does not entail any MIMI
protocol operations.  However, it must establish the initial state of the room,
which is then the basis for protocol operations related to the room.

Here, we assume that Alice uses ClientA1 to create a room with the following
properties:

* Identifier: `clubhouse@a.example`
* Participants: `[alice@a.example]`

ClientA1 also creates an MLS group with group ID `clubhouse@a.example` and
ensures via provider-local operations that Alice's other clients are members of
this MLS group.

## Alice adds Bob to the Room

Adding Bob to the room entails operations at two levels.  First, Bob's user
identity must be added to the room's participant list.  Second, Bob's clients
must be added to the room's MLS group.

The process of adding Bob to the room thus begins by Alice fetching key material
for Bob's clients.  Alice then updates the room by sending an MLS Commit over
the following proposals:

* An AppSync proposal updating the room state by adding Bob to the
  participant list
* Add proposals for Bob's clients

The MIMI protocol interactions are between Alice's server ServerA and Bob's
server ServerB.  ServerB stores KeyPackages on behalf of Bob's devices.  ServerA
performs the key material fetch on Alice's behalf, and delivers the resulting
KeyPackages to Alice's clients.  Both ServerA and ServerB remember the sources
of the KeyPackages they handle, so that they can route a Welcome message for
those KeyPackages to the proper recipients -- ServerA to ServerB, and ServerB to
Bob's clients.

> **NOTE:** In the full protocol, it will be necessary to have consent and access
> control on these operations.  We have elided that step here in the interest of
> simplicity.

~~~ aasvg
ClientA1       ServerA         ServerB         ClientB*
  |               |               |               |
  |               |               |     Store KPs |
  |               |               |<~~~~~~~~~~~~~~+
  |               |               |<~~~~~~~~~~~~~~+
  | Request KPs   |               |               |
  +~~~~~~~~~~~~~~>| /keyMaterial  |               |
  |               +-------------->|               |
  |               |        200 OK |               |
  |           KPs |<--------------+               |
  |<~~~~~~~~~~~~~~+               |               |
  |               |               |               |

ClientB*->ServerB: [[ Store KeyPackages ]]
ClientA1->ServerA: [[ request KPs for bob@b.example ]]
ServerA->ServerB: POST /keyMaterial KeyMaterialRequest
ServerB: Verify that Alice is authorized to fetch KeyPackages
ServerB: Mark returned KPs as reserved for Alice’s use
ServerB->ServerA: 200 OK KeyMaterialResponse
ServerA: Remember that these KPs go to b.example
ServerA->ClientA1: [[ KPs ]]
~~~
{: #fig-ab-kp-fetch title="Alice Fetches KeyPackages for Bob's Clients" }

~~~ aasvg
ClientA1       ServerA         ServerB         ClientB*
  |               |               |               |
  | Commit, etc.  |               |               |
  +~~~~~~~~~~~~~~>| /notify       |               |
  |               +-------------->| Welcome, Tree |
  |               |               +~~~~~~~~~~~~~~>|
  |               |               +~~~~~~~~~~~~~~>|
  |               |        200 OK |               |
  |      Accepted |<--------------+               |
  |<~~~~~~~~~~~~~~+               |               |
  |               |               |               |

ClientA1: Prepare Commit over AppSync(+bob@b.example), Add*
ClientA1->ServerA: [[ Commit, Welcome, GroupInfo?, RatchetTree? ]]
ServerA: Verify that AppSync, Adds are allowed by policy
ServerA: Identifies Welcome domains based on KP hash in Welcome
ServerA->ServerB: POST /notify/clubhouse@a.example Intro{ Welcome, RatchetTree? }
ServerB: Recognizes that Welcome is adding Bob to room clubhouse@a.example
ServerB->ClientB*: [[ Welcome, RatchetTree? ]]
~~~
{: #fig-ab-add title="Alice Adds Bob to the Room and Bob's Clients to the MLS Group" }


## Bob adds Cathy to the Room

The process of adding Bob was a bit abbreviated because Alice is a user of the
hub service provider.  When Bob adds Cathy, we see the full process, involving
the same two steps (KeyPackage fetch followed by Add), but this time indirected via the
hub server ServerA.  Also, now that there are users on ServerB involved in the
room, the hub ServerA will have to distribute the Commit adding Cathy and
Cathy's clients to ServerB as well as forwarding the Welcome to ServerC.

~~~ aasvg
ClientB1       ServerB         ServerA         ServerC         ClientC*
  |               |               |               |               |
  |               |               |               |     Store KPs |
  |               |               |               |<~~~~~~~~~~~~~~+
  |               |               |               |<~~~~~~~~~~~~~~+
  | Request KPs   |               |               |               |
  +~~~~~~~~~~~~~~>| /keyMaterial  | /keyMaterial  |               |
  |               +-------------->+-------------->|               |
  |               |        200 OK |        200 OK |               |
  |           KPs |<--------------+<--------------+               |
  |<~~~~~~~~~~~~~~+               |               |               |
  |               |               |               |               |

ClientC*->ServerC: [[ Store KeyPackages ]]
ClientB1->ServerB: [[ request KPs for bob@b.example ]]
ServerB->ServerA: POST /keyMaterial KeyMaterialRequest
ServerA->ServerC: POST /keyMaterial KeyMaterialRequest
ServerB: Verify that Bob is authorized to fetch KeyPackages
ServerB: Mark returned KPs as reserved for Bob’s use
ServerC->ServerA: 200 OK KeyMaterialResponse
ServerA: Remember that these KPs go to b.example
ServerA->ServerB: 200 OK KeyMaterialResponse
ServerB->ClientB1: [[ KPs ]]
~~~
{: #fig-bc-kp-fetch title="Bob Fetches KeyPackages for Cathy's Clients" }

~~~ aasvg
ClientB1       ServerB         ServerA         ServerC         ClientC*  ClientB*  ClientA*
  |               |               |               |               |         |         |
  | Commit, etc.  |               |               |               |         |         |
  +~~~~~~~~~~~~~~>| /update       |               |               |         |         |
  |               +-------------->|               |               |         |         |
  |               |        200 OK |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |      Accepted |               | /notify       |               |         |         |
  |<~~~~~~~~~~~~~~+               +-------------->| Welcome, Tree |         |         |
  |               |               |               +~~~~~~~~~~~~~~>|         |         |
  |               |               |               +~~~~~~~~~~~~~~>|         |         |
  |               |       /notify |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |               | Commit        |               |               |         |         |
  |               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|         |
  |               |               | Commit        |               |         |         |
  |               |               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|
  |               |               |               |               |         |         |

ClientB1: Prepare Commit over AppSync(+cathy@c.example), Add*
ClientB1->ServerB: [[ Commit, Welcome, GroupInfo?, RatchetTree? ]]
ServerB->ServerA: POST /update/clubhouse@a.example CommitBundle
ServerA: Verify that Adds are allowed by policy
ServerA->ServerB: 200 OK
ServerA->ServerC: POST /notify/clubhouse@a.example Intro{ Welcome, RatchetTree? }
ServerC: Recognizes that Welcome is adding Cathy to clubhouse@a.example
ServerC->ClientC*: [[ Welcome, RatchetTree? ]]
ServerA->ServerB: POST /notify/clubhouse@a.example Commit
ServerB->ClientB*: [[ Commit ]]
ServerA->ClientA*: [[ Commit ]]
~~~
{: #fig-bc-add title="Bob Adds Cathy to the Room and Cathy's Clients to the MLS Group" }

## Cathy Sends a Message

Now that Alice, Bob, and Cathy are all in the room, Cathy wants to say hello to
everyone.  Cathy's client encapsulates the message in an MLS PrivateMessage and
sends it to ServerC, who forwards it to the hub ServerA on Cathy's behalf.
Assuming Cathy is allowed to speak in the room, ServerA will forward Cathy's
message to the other servers involved in the room, who distribute it to their
clients.

~~~ aasvg
ClientC1       ServerC         ServerA         ServerB         ClientB*  ClientC*  ClientA*
  |               |               |               |               |         |         |
  | Message       |               |               |               |         |         |
  +~~~~~~~~~~~~~~>| /submit       |               |               |         |         |
  |               +-------------->|               |               |         |         |
  |               |        200 OK |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |      Accepted |               | /notify       |               |         |         |
  |<~~~~~~~~~~~~~~+               +-------------->| Message       |         |         |
  |               |               |               +~~~~~~~~~~~~~~>|         |         |
  |               |       /notify |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |               | Message       |               |               |         |         |
  |               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|         |
  |               |               | Message       |               |         |         |
  |               |               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|
  |               |               |               |               |         |         |

ClientC1->ServerC: [[ MLSMessage(PrivateMessage) ]]
ServerC->ServerA: POST /submit/clubhouse@a.example MLSMessage(PrivateMessage)
ServerA: Verifies that message is allowed
ServerA->ServerC: POST /notify/clubhouse@a.example Message{ MLSMessage(PrivateMessage) }
ServerA->ServerB: POST /notify/clubhouse@a.example Message{ MLSMessage(PrivateMessage) }
ServerA->ClientA*: [[ MLSMessage(PrivateMessage) ]]
ServerB->ClientB*: [[ MLSMessage(PrivateMessage) ]]
ServerC->ClientC*: [[ MLSMessage(PrivateMessage) ]]
~~~
{: #fig-c-msg title="Cathy Sends a Message to the Room" }

## Bob Leaves the Room

A user removing another user follows the same flow as adding the user.  The
user performing the removal creates an MLS commit covering Remove proposals for
all of the removed user's devices, and an AppSync proposal updating the room
state to remove the removed user from the room's participant list.

One's own user leaving is slightly more complicated than removing another user,
because the leaving user cannot remove all of their devices from the MLS group.
Instead, the leave happens in three steps:

1. The leaving client constructs MLS Remove proposals for all of the user's
   devices (including the leaving client), and an AppSync proposal that removes
   its user from the participant list.
2. The leaving client sends these proposals to the hub.  The hub caches the proposals.
3. The next time a client attempts to commit, the hub requires the client to
   include the cached proposals.

The hub thus guarantees the leaving client that they will be removed as soon as
possible.

~~~ aasvg
ClientB1       ServerB         ServerA         ServerC         ClientC1
  |               |               |               |               |
  | Proposals     |               |               |               |
  +~~~~~~~~~~~~~~>| /update       |               |               |
  |               +-------------->|               |               |
  |               |        200 OK |               |               |
  |               |<--------------+               |               |
  |      Accepted |               |  /notify      |               |
  |<~~~~~~~~~~~~~~+               +-------------->|               |
  |               |               |               | Proposals     |
  |               |               |               +~~~~~~~~~~~~~~>|
  |               |               |               |               |
  |               |               |               | Commit(Props) |
  |               |               |               |<~~~~~~~~~~~~~~+
  |               |               |       /update |               |
  |               |               |<--------------+               |
  |               |               | 200 OK        |               |
  |               |               +-------------->|               |
  |               |               |               | Accepted      |
  |               |               |               +~~~~~~~~~~~~~~>|
  |               |       /notify | /notify       |               |
  |               |<--------------+-------------->|               |
  |               |               |               |               |

ClientB1: Prepare Remove*, AppSync(-bob@b.example)
ClientB1->ServerB: [[ Remove*, AppSync ]]
ServerB->ServerA: POST /update/clubhouse@a.example Remove*, AppSync
ServerA: Verify that Removes, AppSync are allowed by policy; cache
ServerA->ServerB: 200 OK
ServerA->ServerC: POST /notify/clubhouse@a.example Proposals
ServerC1->ClientC1: [[ Proposals ]]
ClientC1->ServerC: [[ Commit(Props), Welcome, GroupInfo?, RatchetTree? ]]
ServerC->ServerA: POST /update/clubhouse@a.example CommitBundle
ServerA: Check whether Commit includes queued proposals; accept
ServerA->ServerC: 200 OK
ServerA->ServerB: POST /notify/clubhouse@a.example Commit
ServerA->ServerC: POST /notify/clubhouse@a.example Commit
~~~
{: #fig-b-leave title="Bob Leaves the Room" }


## Room state

The state of a room consists of the room's RoomID, its policy, and the
participant list (including the role and participation state of each
participant). Also associated with the room is the MLS group managed by the MIMI
DS protocol, which anchors the room state cryptographically as part of the group
state.

While (through the MIMI DS protocol) all parties involved in a room agree on the
room's state, the Hub is the arbiter that decides if a state change is valid.
All state-changing events are sent to the Hub, checked for their validity and
policy conformance before they are forwarded to any follower servers.

As soon as the Hub accepts an event that changes the room state, its effect is
applied to the room state and future events are validated in the context of that
new state.

The room state is thus changed based on events, even if the MLS proposal
implementing the event was not yet committed by a client. Note that this only
applies to events changing the room state, but not for MIMI DS specific events
that change the group state. For more information on the proposal-commit
paradigm and the role of the MIMI DS protocol see {{mimi-ds}}.

## Cryptographic room representation {#mimi-ds}

Each room is represented cryptographically by an MLS group and the Hub that
manages the room uses the MIMI DS protocol specified in
{{!I-D.robert-mimi-delivery-service}} to manage that group.

In particular, the MIMI DS protocol manages the list of group members, i.e. the
list of clients belonging to users currently in the room.

### Proposal-commit paradigm

The MIMI DS protocol uses MLS, which follows a proposal-commit paradigm. Any
party involved in a room (follower server, Hub or clients) can send proposals
(e.g. to add/remove/update clients of a user or to re-initialize the group with
different parameters). However, only clients can send commits, which contain all
valid previously sent proposals and apply them to the MLS group state.

The MIMI DS protocol ensures that the Hub, all follower servers and the clients
of all participants (or at least those in the `join` state) agree on the group
state, which includes the client list and the key material used for message
encryption (although the latter is only available to clients). Since the group
state also includes a copy of the room state at the time of the most recent
commit, it is also covered by the agreement.

### Cryptographically anchoring room state {#anchoring}

To allow all parties involved to agree on the state of the room in addition to
the state of the associated group, the room state is anchored in the MLS group
via a GroupContext extension.

~~~ tls
struct {
   opaque user_id;
   opaque role;
   ParticipationState state;
} ParticipantData

struct {
  opaque room_id;
  ParticipantData participants<V>;
  // TODO: Add any remaining room data
} RoomState;
~~~

As part of the MIMI DS protocol, clients create commits to update the group
state, which are then included in MIMI DS specific events. The time between two
commits denotes an epoch.

Whenever a client creates a commit, it MUST include all valid proposals accepted
by the Hub during the current epoch. This includes both proposals that carry
room-state changes, as well as proposals sent as part of MIMI DS events.

Note that the validity of a proposal depend on the current room state, which may
change during an epoch based on room-state changing events. The changes of these
events are applied to the room state even if the commits that carry the event
information have not yet been committed.

### Authenticating proposals

The MLS specification {{!RFC9420}} requires that MLS proposals from the Hub and
from follower servers (external senders in MLS terminology) be authenticated
using key material contained in the `external_senders` extension of the MLS
group. Each MLS group associated with a MIMI room MUST therefore contain an
`external_senders` extension. That extension MUST contain at least the
Certificate of the Hub.

When a user from a follower server becomes a participant in the room, the
Certificate of the follower server MAY be added to the extension. When the last
participant belonging to a follower server leaves the room, the certificate of
that user MUST be removed from the list. Changes to the `external_senders`
extension only take effect when the MLS proposal containing the event is
committed by a MIMI DS commit. See {{ev-mroomuser}} for more information.


# MLS Application State Synchronization

**TODO:** This section should be moved to its own document in the MLS working group.

One of the primary security benefits of MLS is that the MLS key schedule
confirms that the group agrees on certain metadata, such as the membership of
the group. Members that disagree on the relevant metadata will arrive at
different keys and be unable to communicate. Applications based on MLS can
integrate their state into this metadata in order to confirm that the members of
an MLS group agree on application state as well as MLS metadata.

Here, we define two extensions to MLS to facilitate this application design:

1. A GroupContext extension `application_states` that confirms agreement on
   application state from potentially multiple sources.
2. A new proposal type AppSync that allows MLS group members to propose changes
   to the agreed application state.

The `application_states` extension allows the application to inject state
objects into the MLS key schedule. Changes to this state can be made out of
band, or using the AppSync proposal. Using the AppSync proposal ensures that
members of the MLS group have received the relevant state changes before they
are reflected in the group's `application_states`.

> **NOTE:** This design exposes the high-level structure of the application state
> to MLS.  An alternative design would be to have the application state be opaque
> to MLS.  There is a trade-off between generality and the complexity of the API
> between the MLS implementation and the application.  An opaque design would give
> the application more freedom, but require the MLS stack to call out to the
> application to get the updated state as part of Commit processing.  This design
> allows the updates to happen within the MLS stack, so that no callback is
> needed, at the cost of forcing the application state to fit a certain structure.
> It also potentially can result in smaller state updates in large groups.

The state for Each `applicationId` in the `application_states` needs to conform
to one of four basic types: an ordered array, an unordered array, a map, or an
irreducible blob. This allows the AppSync proposal to efficiently modify a large
application state object.

The content of the `application_states` extension and the `AppSync` proposal are
structured as follows:

~~~ tls
enum {
    irreducible(0),
    map(1),
    unorderedList(2),
    orderedArray(3),
    (255)
} StateType;

struct {
  opaque element<V>;
} OpaqueElement;

struct {
  opaque elementName<V>;
  opaque elementValue<V>;
} OpaqueMapElement;

struct {
  uint32 applicationId;
  StateType stateType;
  select (stateType) {
    case irreducible:
      OpaqueElement state;
    case map:
      OpaqueMapElement mapEntries<V>;
    case unorderedList:
      OpaqueElement unorderedEntries<V>;
    case orderedArray:
      OpaqueElement orderedEntries<V>;
  };
} ApplicationState;

struct {
  ApplicationState applicationStates<V>;
} ApplicationStatesExtension;
~~~
{: #fig-app-state title="The `application_state` extension" }

~~~ tls
struct {
  uint32 index;
  opaque element<V>;
} ElementWithIndex;


struct {
  uint32 applicationId;
  StateType stateType;
  select (stateType) {
    case irreducible:
      OpaqueElement newState;
    case map:
      OpaqueElement removedKeys<V>;
      OpaqueMapElement newOrUpdatedElements<V>;
    case unorderedList:
      uint32 removedIndices<V>;
      OpaqueElement addedEntries<V>;
    case orderedArray:
      ElementWithIndex replacedElements<V>;
      uint32 removedIndices<V>;
      ElementWithIndex insertedElements<V>;
      OpaqueElement appenededEntries<V>;
  };
} AppSync;
~~~
{: #fig-app-sync title="The AppSync proposal type" }

The `applicationId` determines the structure and interpretation of the contents.
of an ApplicationState object. AppSync proposals
contain changes to this state, which the client uses to update the
representation of the state in `application_states`.

A client receiving an AppSync proposal applies it in the following way:

* Identify an `application_states` GroupContext extension which contains the
  same `application_id` state as the AppSync proposal
* Apply the relevant operations (replace, remove, update, append, insert)
  according to the `stateType` to the relevant parts of the ApplicationState
  object in `application_states` extension.

An AppSync for an irreducible state replaces its `state` element with a new
(possibly empty) `newState`. An AppSync for a map-based ApplicationState first
removes all the keys in `removedKeys` and than replaces or adds the elements in
`newOrUpdatedElements`. An AppSync for an unorderedList ApplicationState first
removes all the indexes in `removedIndices`, then adds the elements in
`addedEntries`. Finally an AppSync for an orderedArray, replaces all the
elements (index-by-index) in `replacedElements`, the removes the elements in
`removedIndices` according to the then order of the array, then inserts all the
elements in `insertedElements` according to the then order of the array, then
finally appends the `appendedEntries` (in order). All indices are zero-based.

Note that the `application_states` extension is updated directly by AppSync
proposals; a GroupContextExtensions proposal is not necessary. A proposal list
that contains both an AppSync proposal and a GroupContextExtensions proposal
is invalid.

Likewise a proposal list in a Commit MAY contain more than one AppSync proposal,
but no more than one AppSync proposal per `applicationId`. The proposals are
applied in the order that they are sent in the Commit.

AppSync proposals do not need to contain an UpdatePath. An AppSync proposal can
be sent by an authorized external sender.

> **TODO:** IANA registry for `application_id`; register extension and proposal types
>as safe extensions

# Security Considerations

Overall, the user participation state leads any possible MLS group state to
ensure malicious clients are not able to easily get access to messages.

> **TODO**: Other security guarantees? Consensus may be required here.

# IANA Considerations


--- back

# Acknowledgments
{:numbered="false"}

> **TODO**: Refactor acknowledgements to match sections of interest.

This document is the consolidation of the following documents:

* {{?I-D.kohbrok-mimi-transport}},

* {{?I-D.robert-mimi-delivery-service}},

* {{?I-D.ralston-mimi-signaling}},

* {{?I-D.ralston-mimi-policy}},

* {{?I-D.mahy-mimi-group-chat}},

{{!I-D.barnes-mimi-arch}} was additionally used throughout the writing
of this document.
