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
    fullname: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    fullname: Matthew Hodgson
    organization: The Matrix.org Foundation C.I.C.
    email: matthew@matrix.org
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad.kohbrok@datashrine.de
 -
    fullname: Rohan Mahy
    organization: Unaffiliated
    email: rohan.ietf@gmail.com
 -
    fullname: Travis Ralston
    organization: The Matrix.org Foundation C.I.C.
    email: travisr@matrix.org
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

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
: In this document, we introduce a notional concept of roles for
participants, and permissions for roles. Actual messaging systems have more
complex and well-specified authorization policies about which clients can
take which actions in a room.

Advanced join/leave flows:
: In this document, all adds / removes / joins / leaves are initiated from
within the group, or by a new joiner who already has permission to join,
as this aligns well with MLS.  Messaging applications
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
* Users Alice (`alice`), Bob (`bob`) and Cathy (`cathy`) of the service providers `a.example`, `b.example`, and `c.example` respectively.
* Clients `ClientA1`, `ClientA2`, `ClientB1`, etc. belonging to these users
* A room `clubhouse` hosted by hub provider `a.example` where the three users interact.

Inside the protocol, each provider is represented by a domain name in the
`host` production of the `authority` of a MIMI URI {{!RFC3986}}. Specific
hosts or servers are represented by domain names, but not by MIMI URIs.
Examples of different types of identifiers represented in a MIMI URI are
shown in the table below:

| Identifier type | Example URI |
|-+-|
| Provider  | `mimi://a.example`             |
| User      | `mimi://a.example/u/alice`     |
| Client    | `mimi://a.example/d/ClientA1`  |
| Room      | `mimi://a.example/r/clubhouse` |
| MLS group | `mimi://a.example/g/clubhouse` |
{: #mimi-uri-examples title="MIMI URI examples"}

As noted in {{!I-D.barnes-mimi-arch}}, the MIMI protocol only defines interactions
between service providers' servers.  Interactions between clients and servers
within a service provider domain are shown here for completeness, but
surrounded by `[[ double brackets ]]`.

## Alice Creates a Room

The first step in the lifetime of a MIMI room is its creation on the hub server.
This operation is local to the service provider, and does not entail any MIMI
protocol operations.  However, it must establish the initial state of the room,
which is then the basis for protocol operations related to the room.

For authorization purposes, MIMI uses permissions based on room-defined roles.
For example, a room might have a role named "admin", which has `canAddUser`,
`canRemoveUser`, and `canSetUserRole` permisions.

Here, we assume that Alice uses ClientA1 to create a room with the following
base policy properties:

* Room Identifier: `mimi://a.example/r/clubhouse`
* Roles: `admin = [canAddUser, canRemoveUser, canSetUserRole]`

And the following participant list:

* Participants: `[[mimi://a.example/u/alice, "admin"]]`

ClientA1 also creates an MLS group with group ID `mimi://a.example/g/clubhouse` and
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
ClientA1->ServerA: [[ request KPs for Bob ]]
ServerA->ServerB: POST /keyMaterial KeyMaterialRequest
ServerB: Verify that Alice is authorized to fetch KeyPackages
ServerB: Mark returned KPs as reserved for Alice's use
ServerB->ServerA: 200 OK KeyMaterialResponse
ServerA: Remember that these KPs go to b.example
ServerA->ClientA1: [[ KPs ]]
~~~
{: #fig-ab-kp-fetch title="Alice Fetches KeyPackages for Bob's Clients" }

~~~ aasvg
ClientA1       ServerA         ServerB         ClientB*
  |               |               |               |
  | Commit, etc.  |               |               |
  +~~~~~~~~~~~~~~>|               |               |
  |      Accepted | /notify       |               |
  |<~~~~~~~~~~~~~~+-------------->|               |
  |               |        200 OK | Welcome, Tree |
  |               |<--------------+~~~~~~~~~~~~~~>|
  |               |               +~~~~~~~~~~~~~~>|
  |               |               |               |


ClientA1: Prepare Commit over AppSync(+Bob), Add*
ClientA1->ServerA: [[ Commit, Welcome, GroupInfo?, RatchetTree? ]]
ServerA: Verify that AppSync, Adds are allowed by policy
ServerA: Identifies Welcome domains based on KP hash in Welcome
ServerA->ServerB: POST /notify/a.example/r/clubhouse Intro{ Welcome, RatchetTree? }
ServerB: Recognizes that Welcome is adding Bob to room clubhouse
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
ClientB1->ServerB: [[ request KPs for Bob ]]
ServerB->ServerA: POST /keyMaterial KeyMaterialRequest
ServerA->ServerC: POST /keyMaterial KeyMaterialRequest
ServerB: Verify that Bob is authorized to fetch KeyPackages
ServerB: Mark returned KPs as reserved for Bob's use
ServerC->ServerA: 200 OK KeyMaterialResponse
ServerA: Remember that these KPs go to b.example
ServerA->ServerB: 200 OK KeyMaterialResponse
ServerB->ClientB1: [[ KPs ]]
~~~
{: #fig-bc-kp-fetch title="Bob Fetches KeyPackages for Cathy's Clients" }

~~~ aasvg
Client                                         Client    Client  Client
B1         ServerB     ServerA     ServerC      C*        B*        A*
|             |           |           |           |         |         |
| Commit, etc |           |           |           |         |         |
+~~~~~~~~~~~~>| /update   |           |           |         |         |
|             +---------->|           |           |         |         |
|             |    200 OK |           |           |         |         |
|             |<----------+           |           |         |         |
|    Accepted |           | /notify   | Welcome,  |         |         |
|<~~~~~~~~~~~~+           +---------->| Tree      |         |         |
|             |           |           +~~~~~~~~~~>|         |         |
|             |   /notify | Commit    +~~~~~~~~~~>|         |         |
|             |<----------+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|
|             | Commit    |           |           |         |         |
|             +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|         |
|             |           |           |           |         |         |

ClientB1: Prepare Commit over AppSync(+Cathy), Add*
ClientB1->ServerB: [[ Commit, Welcome, GroupInfo?, RatchetTree? ]]
ServerB->ServerA: POST /update/a.example/r/clubhouse CommitBundle
ServerA: Verify that Adds are allowed by policy
ServerA->ServerB: 200 OK
ServerA->ServerC: POST /notify/a.example/r/clubhouse
                       Intro{ Welcome, RatchetTree? }
ServerC: Recognizes that Welcome is adding Cathy to clubhouse
ServerC->ClientC*: [[ Welcome, RatchetTree? ]]
ServerA->ServerB: POST /notify/a.example/r/clubhouse Commit
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
ServerC->ServerA: POST /submit/a.example/r/clubhouse MLSMessage(PrivateMessage)
ServerA: Verifies that message is allowed
ServerA->ServerC: POST /notify/a.example/r/clubhouse Message{ MLSMessage(PrivateMessage) }
ServerA->ServerB: POST /notify/a.example/r/clubhouse Message{ MLSMessage(PrivateMessage) }
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
ClientB1       ServerB         ServerA         ServerC         ClientC1  C2
  |               |               |               |               |       |
  | Proposals     |               |               |               |       |
  +~~~~~~~~~~~~~~>| /update       |               |               |       |
  |               +-------------->|               |               |       |
  |               |        200 OK |               |               |       |
  |               |<--------------+               |               |       |
  |      Accepted |               |  /notify      |               |       |
  |<~~~~~~~~~~~~~~+               +-------------->|               |       |
  |               |               |               | Proposals     |       |
  |               |               |               +~~~~~~~~~~~~~~>|       |
  |               |               |               |               |       |
  |               |               |               | Commit(Props) |       |
  |               |               |               |<~~~~~~~~~~~~~~+       |
  |               |               |       /update |               |       |
  |               |               |<--------------+               |       |
  |               |               | 200 OK        |               |       |
  |               |               +-------------->|               |       |
  |               |               |               | Accepted      |       |
  |               |               |               +~~~~~~~~~~~~~~>|       |
  |               |       /notify | /notify       |               |       |
  |        Commit |<--------------+-------------->| Commit        |       |
  |<~~~~~~~~~~~~~~+               |               +~~~~~~~~~~~~~~~~~~~~~~>|
  |               |               |               +~~~~~~~~~~~~~~>|       |
  |               |               |               |               |       |

ClientB1: Prepare Remove*, AppSync(-Bob)
ClientB1->ServerB: [[ Remove*, AppSync ]]
ServerB->ServerA: POST /update/a.example/r/clubhouse Remove*, AppSync
ServerA: Verify that Removes, AppSync are allowed by policy; cache
ServerA->ServerB: 200 OK
ServerA->ServerC: POST /notify/a.example/r/clubhouse Proposals
ServerC1->ClientC1: [[ Proposals ]]
ClientC1->ServerC: [[ Commit(Props), Welcome, GroupInfo?, RatchetTree? ]]
ServerC->ServerA: POST /update/a.example/r/clubhousee CommitBundle
ServerA: Check whether Commit includes queued proposals; accept
ServerA->ServerC: 200 OK
ServerA->ServerB: POST /notify/a.example/r/clubhouse Commit
ServerA->ServerC: POST /notify/a.example/r/clubhouse Commit
ServerB->ClientB1: [[ Commit ]]
ServerC->ClientC2: [[ Commit ]]
ServerC->ClientC1: [[ Commit ]] (up to provider)
~~~
{: #fig-b-leave title="Bob Leaves the Room" }

## Cathy adds a new device

Many users have multiple clients often running on different devices
(for example a phone, a tablet, and a computer). When a user creates a new
client, that client needs to be able to join all the MLS groups associated
with the rooms in which the user is a participant.

In MLS in order to initiate joining a group the joining client needs to get the current GroupInfo
and `ratchet_tree`, and then send an External Commit to the hub. In MIMI,
the hub keeps or reconstructs a copy of the GroupInfo, assuming that other
clients may not be available to assist the client with joining.

For Cathy's new client (ClientC3) to join the MLS group and therefore fully participate
in the room with Alice, ClientC3 needs to fetch the MLS GroupInfo, and then
generate an External Commit adding ClientC3.

Cathy's new client sends the External Commit to the room's MLS group by sending
an /update to the room.

~~~ aasvg
ClientC3       ServerC         ServerA         ServerB         ClientB*  ClientC*  ClientA*
  |               |               |               |               |         |         |
  | Fetch         |               |               |               |         |         |
  | GroupInfo     |               |               |               |         |         |
  |~~~~~~~~~~~~~~>| /groupInfo    |               |               |         |         |
  |               |-------------->|               |               |         |         |
  | GroupInfo +   |        200 OK |               |               |         |         |
  | tree          |<--------------|               |               |         |         |
  |<~~~~~~~~~~~~~~|               |               |               |         |         |
  |               |               |               |               |         |         |
  | External      |               |               |               |         |         |
  | Commit, etc.  |               |               |               |         |         |
  +~~~~~~~~~~~~~~>| /update       |               |               |         |         |
  |               +-------------->|               |               |         |         |
  |               |        200 OK |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |      Accepted |               | Commit        |               |         |         |
  |<~~~~~~~~~~~~~~|               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|
  |               |               |               |               |         |         |
  |               |               | /notify       |               |         |         |
  |               +               +-------------->| Commit        |         |         |
  |               |               |               +~~~~~~~~~~~~~~>|         |         |
  |               |       /notify |               |               |         |         |
  |               |<--------------+               |               |         |         |
  |               | Commit        |               |               |         |         |
  |               +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>|         |
  |               |               |               |               |         |         |

ClientC3->ServerC: [[ request current GroupInfo ]]
ServerC->ServerA: POST /groupInfo/a.example/clubhouse
ServerA: Verify that ClientC3 has authorization to join the room
ServerA->ServerC: 200 OK w/ current GroupInfo and ratchet tree
ServerC->ClientC3: [[ GroupInfo, tree ]]
ClientC3: Prepare External Commit Add*
ClientC3->ServerC: [[ Commit, GroupInfo?, RatchetTree? ]]
ServerC->ServerA: POST /update/a.example/clubhouse CommitBundle
ServerA: Verify that Commit is valid and ClientC3 is authorized
ServerA->ServerC: 200 OK
ServerC->ClientC3: [[ External Commit was accepted ]]
ServerA->ClientA*: [[ Commit ]]
ServerA->ServerB: POST /notify/a.example/clubhouse Commit
ServerB->ClientB*: [[ Commit ]]
ServerA->ServerC: POST /notify/a.example/clubhouse Commit
ServerC->ClientC*: [[ Commit ]]
~~~
{: #fig-c3-new-client title="Cathy Adds a new Client" }


# Services required at each layer

## Transport layer

MIMI servers communicate using HTTPS.  The HTTP request MUST identify the
source and target providers for the request, in the following way:

* The target provider is indicated using a Host header {{!RFC9110}}.  If the
  provider is using a non-standard port, then the port component of the Host
  header is ignored.
* The source provider is indicated using a From header {{!RFC9110}}.  The
  `mailbox` production in the From header MUST use the `addr-spec` variant, and
  the `local-part` of the address MUST contain the fixed string `mimi`.  Thus,
  the content of the From header will be `mimi@a.example`, where `a.example` is
  the domain name of the source provider.

> **NOTE**: The use of the From header field here is not really well-aligned with its
  intended use.  The WG should consider whether this is correct, or whether a new
  header field would be better.  Perhaps something like "From-Host" to match Host?

The TLS connection underlying the HTTPS connection MUST be mutually
authenticated.  The certificates presented in the TLS handshake MUST
authenticate the source and target provider domains, according to {{!RFC6125}}.

The bodies of HTTP requests and responses are defined by the individual
endpoints defined in {{application-layer}}.

## End-to-End Security Layer

Every MIMI room has an MLS group associated to it, which provides end-to-end
security guarantees.  The clients participating in the room manage the MLS-level
membership by sending Commit messages covering Add and Remove proposals.

Every application message sent within a room is authenticated and confidentiality-protected
by virtue of being encapsulated in an MLS PrivateMessage object.

MIMI uses the MLS application state synchronization mechanism
({{mls-application-state-synchronization}}) to ensure that the clients involved
in a MIMI room agree on the state of the room.  Each MIMI message that changes
the state of the room is encapsulated in an AppSync proposal and transmitted
inside an MLS PublicMessage object.

The PublicMessage encapsulation provides sender authentication, including the
ability for actors outside the group (e.g., servers involved in the room) to
originate AppSync proposals.  Encoding room state changes in MLS proposals
ensures that a client will not process a commit that confirms a state change
before processing the state change itself.

> **TODO**: A little more needs to be said here about how MLS is used.  For
example: What types of credential are required / allowed?  If servers are going
to be allowed to introduce room changes, how are their keys provisioned as
external signers? Need to maintain the membership and the list of queued proposals.

## Application Layer

Servers in MIMI provide a few functions that enable messaging applications.
All servers act as publication points for key material used to add their users
to rooms. The hub server for a room tracks the state of the room, and controls
how the room's state evolves, e.g., by ensuring that changes are compliant with
the room's policy. Non-hub servers facilitate interactions between their clients
and the hub server.

In this section, we describe the state that servers keep. The following top
level section describes the HTTP endpoints exposed to enable these functions.

### Server State

Every MIMI server is a publication point for users' key material, via the
`keyMaterial` endpoint discussed in {{fetch-key-material}}.  To support this
endpoint, the server stores a set of KeyPackages, where each KeyPackage belongs
to a specific user and device.

Each KeyPackage includes a list of its MLS client's capabilities (MLS
protocol versions, cipher suites, extensions, proposal types, and credential
types). When claiming KeyPackages, the requester includes the list of
`RequiredCapabilites` to ensure the new joiner is compatible with and
capable of participating in the corresponding room.

The hub server for the room stores the state of the room, comprising:

* The *base policy* of the room, which does not depend on the specific
  participants in the room. For example, this includes the room roles
  and their permissions.
* The *participant list*: a list of the users who are participants of the
  room, and each user's role in the room.

> **TODO**: We need a more full description of the room, room state syntax.

When a client requests key material via the hub, the hub records the
KeyPackageRef values for the returned KeyPackages, and the identity of the
provider from which they were received.  This information is then used to route
Welcome message to the proper provider.

### Participant List Changes

The participant list can be changed by adding or removing users, or changing
a user's role.  These changes are described without a specific syntax as a
list of adds, removes, and role changes:

~~~ ascii-art
Add: ["mimi://d.example/u/diana", "admin"],
     ["mimi://e.example/u/eric", "admin"],
Remove: ["mimi://b.example/u/bob"],
SetRole: [["mimi://c.example/u/cathy", "admin"]]
~~~
{: #fig-room-state-change title="Changing the state of the room" }

To put these changes into effect, a client or server encodes them in an AppSync
proposal, signs the proposal as a PublicMessage, and submits them to the
`update` endpoint on the hub.

# MIMI Endpoints and Framing

This section describes the specific endpoints necessary to provide the
functionality in the example flow. The framing for each endpoint includes a
protocol so that different variations of the end-to-end encryption can be used.

> **TODO**: Determine the what needs to be included in the protocol. MIMI
  version, e2e protocol version, etc.

The syntax of the MIMI protocol messages are described using the TLS
presentation language format ({{Section 3 of RFC8446}}).

~~~ tls
enum {
    reserved(0),
    mls10(1),
    (255)
} Protocol;
~~~

## Directory

Like the ACME protocol (See {{Section 7.1.1 of ?RFC8555}}), the MIMI protocol uses a directory document
to convey the HTTPS URLs used to reach certain endpoints (as opposed to hard
coding the endpoints).

The directory URL is discovered using the `mimi-protocol-directory` well-known
URI. The response is a JSON document with URIs for each type of endpoint.

~~~
GET /.well-known/mimi-protocol-directory
~~~

~~~
{
  "keyMaterial":
     "https://mimi.example.com/v1/keyMaterial/{targetUser}",
  "update": "https://mimi.example.com/v1/update{roomId}",
  "notify": "https://mimi.example.com/v1/notify/{roomId}",
  "submitMessage":
     "https://mimi.example.com/v1/submitMessage/{roomId}",
  "groupInfo":
     "https://mimi.example.com/v1/groupInfo/{roomId}"
}
~~~

## Fetch Key Material

This action attempts to claim initial keying material for all the clients
of a single user at a specific provider. The keying material is designed
for use in a single room and may not be reused. It uses the HTTP POST method.

~~~
POST /keyMaterial/{targetUser}
~~~

The target user's URI is listed in the request path. KeyPackages
requested using this primitive MUST be sent via the hub provider of whatever
room they will be used in. (If this is not the case, the hub provider will be
unable to forward a Welcome message to the target provider).

The path includes the target user. The request body includes the protocol
(currently just MLS 1.0), and the requesting user. When the request is being
made in the context of adding the target user to a room, the request MUST include
the room ID for which the KeyPackage is intended, as the target may have only
granted consent for a specific room.

For MLS, the request includes a non-empty list of acceptable MLS ciphersuites,
and an MLS `RequiredCapabilities` object (which contains credential types,
non-default proposal types, and extensions) required by the requesting provider
(these lists can be an empty).

The request body has the following form.

~~~ tls
struct {
    opaque uri<V>;
} IdentifierUri;

struct {
    Protocol protocol;
    IdentifierUri requestingUser;
    IdentifierUri targetUser;
    IdentifierUri roomId;
    select (protocol) {
        case mls10:
            CipherSuite acceptableCiphersuites<V>;
            RequiredCapabilities requiredCapabilities;
    };
} KeyMaterialRequest;
~~~

The response contains a user status code that indicates keying material was
returned for all the user's clients (`success`), that keying material was
returned for some of their clients (`partialSuccess`), or a specific user code
indicating failure. If the user code is success or partialSuccess, each client
is enumerated in the response. Then for each client with a *client* success
code, the structure includes initial keying material (a KeyPackage for MLS 1.0).
If the client's code is `nothingCompatible`, the client's capabilities are
optionally included (The client's capabilities could be omitted for privacy
reasons.)

If the *user* code is `noCompatibleMaterial`, the provider MAY populate the
`clients` list. For any other user code, the provider MUST NOT populate the
`clients` list.

Keying material provided from one response MUST NOT be provided in any other
response.
The target provider MUST NOT provide expired keying material (ex: an MLS
KeyPackage containing a LeafNode with a `notAfter` time past the current date
and time).

~~~ tls
enum {
    success(0);
    partialSuccess(1);
    incompatibleProtocol(2);
    noCompatibleMaterial(3);
    userUnknown(4);
    noConsent(5);
    noConsentForThisRoom(6);
    userDeleted(7);
    (255)
} KeyMaterialUserCode;

enum {
    success(0);
    keyMaterialExhausted(1),
    nothingCompatible(2),
    (255)
} KeyMaterialClientCode;


struct {
    KeyMaterialClientCode clientStatus;
    IdentifierUri clientUri;
    select (protocol) {
        case mls10:
            select (clientStatus) {
                case success:
                    KeyPackage keyPackage;
                case nothingCompatible:
                    optional<Capabilities> clientCapabilities;
            };
    };
} ClientKeyMaterial;

struct {
    Protocol protocol;
    KeyMaterialUserCode userStatus;
    IdentifierUri userUri;
    ClientKeyMaterial clients<V>;
} KeyMaterialResponse;
~~~

The semantics of the `KeyMaterialUserCode` are as follows:

- `success` indicates that key material was provided for every client of the
target user.
- `partialSuccess` indicates that key material was provided for at least one
client of the target user.
- `incompatibleProtocol` indicates that either one of providers supports the
protocol requested, or none of the clients of the target user support the
protocol requested.
- `noCompatibleMaterial` indicates that none of the clients was able to
supply key material compatible with the `requiredCapabilities` field in the
request.
- `userUnknown` indicates that the target user is not known to the target
provider.
- `noConsent` indicates that the requester does not have consent to fetch
key material for the target user. The target provider can use this response
as a catch all and in place of other status codes such as `userUnknown` if
desired to preserve the privacy of its users.
- `noConsentForThisRoom` indicates that the target user might have allowed
a request for another room, but does not for this room. If the provider
does not wish to make this distinction, it can return `noConsent` instead.
- `userDeleted` indicates that the target provider wishes the requester to
know that the target user was previously a valid user of the system and has
been deleted. A target provider can of course use `userUnknown` if the
provider does wish to keep or specify this distinction.

The semantics of the `KeyMaterialClientCode` are as follows:

- `success` indicates that key material was provided for the specified
client.
- `keyMaterialExhausted` indicates that there was no keying material
available for the specified client.
- `nothingCompatible` indicates that the specified clients had no key
material compatible with the `requiredCapabilities` field in the request.

At minimum, as each MLS KeyPackage is returned to a requesting provider (on
behalf of a requesting IM client), the target provider needs to associate its
`KeyPackageRef` with the target client and the hub provider needs to associate
its `KeyPackageRef` with the target provider. This ensures that Welcome messages
can be correctly routed to the target provider and client. These associations
can be deleted after a Welcome message is forwarded or after the KeyPackage
`leaf_node.lifetime.not_after` time has passed.


## Update Room State

Adds, removes, and policy changes to the room are all forms of updating the
room state. They are accomplished using the update transaction which is used to
update the room base policy, participation list, or its underlying MLS group.
It uses the HTTP POST method.

~~~
POST /update/{roomId}
~~~

Any change to the participant list or room policy (including
authorization policy) is communicated via an `AppSync` proposal type
with the `applicationId` of `mimiParticipantList` or `mimiRoomPolicy`
respectively. When adding a user, the proposal containing the participant list
change MUST be committed either before or simultaneously with the corresponding
MLS operation.

Removing an active user from a participant list or banning an active participant
likewise also happen simultaneously with any MLS changes made to the commit removing
the participant.

A hub provider which observes that an active participant has been removed or
banned from the room, MUST prevent any of its clients from sending or
receiving any additional application messages in the corresponding MLS group;
MUST prevent any of those clients from sending Commit messages in that group;
and MUST prevent it from sending any proposals except for `Remove` and
`SelfRemove` {{!I-D.ietf-mls-extensions}} proposals for its users in that group.

The update request body is described below:

~~~ tls
enum {
  reserved(0),
  full(1),
  (255)
} RatchetTreeRepresentation;

struct {
  RatchetTreeRepresentation representation;
  select (representation) {
    case full:
      Node ratchet_tree<V>;
  };
} RatchetTreeOption;

struct {
  select (room.protocol) {
    case mls10:
      PublicMessage proposalOrCommit;
      select (proposalOrCommit.content.content_type) {
        case commit:
          /* Both the Welcome and GroupInfo omit the ratchet_tree */
          optional<Welcome> welcome;
          GroupInfo groupInfo;
          RatchetTreeOption ratchetTreeOption;
        case proposal:
          PublicMessage moreProposals<V>; /* a list of additional proposals */
      };
  };
} UpdateRequest;
~~~

For example, in the first use case described in the Protocol Overview, Alice creates a Commit
containing an AppSync proposal adding Bob (`mimi://b.example/b/bob`), and Add proposals for all
Bob's MLS clients.  Alice includes the Welcome message which will be sent for
Bob, a GroupInfo object for the hub provider, and complete `ratchet_tree`
extension.

The response body is described below:

~~~ tls
enum {
  success(0),
  wrongEpoch(1),
  notAllowed(2),
  invalidProposal(3),
  (255)
} UpdateResponseCode;

struct {
  UpdateResponseCode responseCode;
  string errorDescription;
  select (responseCode) {
    case success:
      /* the hub acceptance time (in milliseconds from the UNIX epoch) */
      uint64 acceptedTimestamp;
    case wrongEpoch:
      /* current MLS epoch for the MLS group */
      uint64 currentEpoch;
    case invalidProposal:
      ProposalRef invalidProposals<V>;
  };
} UpdateRoomResponse
~~~

The semantics of the `UpdatedResponseCode` values are as follows:

- `success` indicates the `UpdateRequest` was accepted and will be distributed.
- `wrongEpoch` indicates that the hub provider is using a different epoch. The
`currentEpoch` is provided in the response.
- `notAllowed` indicates that some type of policy or authorization prevented the
hub provider from accepting the `UpdateRequest`.
- `invalidProposal` indicates that at least one proposal is invalid. A list of
invalidProposals is provided in the response.

## Submit a Message

End-to-end encrypted (application) messages are submitted to the hub for
authorization and eventual fanout using an HTTP POST request.

~~~
POST /submitMessage/{roomId}
~~~

The request body is as follows:

~~~ tls
struct {
  Protocol protocol;
  select(protocol) {
    case mls10:
      /* PrivateMessage containing an application message */
      MLSMessage appMessage;
  };
} SubmitMessageRequest;
~~~

If the protocol is MLS 1.0, the request body is an MLSMessage with a WireFormat
of PrivateMessage (an application message).

The response merely indicates if the message was accepted by the hub provider.

~~~ tls
enum {
  accepted(0),
  notAllowed(1),
  epochTooOld(2),
  (255)
} SubmitResponseCode;

struct {
  Protocol protocol;
  select(protocol) {
    case mls10:
      SubmitResponseCode statusCode;
      select (statusCode) {
        case success:
          /* the hub acceptance time
             (in milliseconds from the UNIX epoch) */
          uint64 acceptedTimestamp;
        case epochTooOld:
          /* current MLS epoch for the MLS group */
          uint64 currentEpoch;
      };
  };
} SubmitMessageResponse;
~~~

The semantics of the `SubmitResponseCode` values are as follows:

- `success` indicates the `SubmitMessageRequest` was accepted and will be distributed.
- `notAllowed` indicates that some type of policy or authorization prevented the
hub provider from accepting the `UpdateRequest`. This could include
nonsensical inputs such as an MLS epoch more recent than the hub's.
- `epochTooOld` indicates that the hub provider is using a new MLS epoch
for the group. The `currentEpoch` is provided in the response.

> **ISSUE:** Do we want to offer a distinction between regular application
messages and ephemeral applications messages (for example "is typing"
notifications), which do not need to be queued at the target provider.

## Fanout Messages and Room Events

If the hub provider accepts an application or handshake message (proposal or
commit) message, it forwards that message to all other providers with active
participants in the room and all local clients which are active members.
This is described as fanning the message out. One can think of fanning a
message out as presenting an ordered list of MLS-protected events to the next
"hop" toward the receiving client.

An MLS Welcome message is sent to the providers and local users associated with
the `KeyPackageRef` values in the `secrets` array of the Welcome. In the case
of a Welcome message, a `RatchetTreeOption` is also included in the
FanoutMessage.

The hub provider also fans out any messages which originate from itself (ex: MLS
External Proposals).

The hub can include multiple concatenated `FanoutMessage` objects relevant to
the same room. This endpoint uses the HTTP POST method.

~~~
POST /notify/{roomId}
~~~

~~~ tls
struct {
  /* the hub acceptance time (in milliseconds from the UNIX epoch) */
  uint64 timestamp;
  select (protocol) {
    case mls10:
      /* A PrivateMessage containing an application message,
         a PublicMessage containing a proposal or commit,
         or a Welcome message.                               */
      MLSMessage message;
      select (message.wire_format) {
        case welcome:
          RatchetTreeOption ratchetTreeOption;
      };
  };
} FanoutMessage;
~~~

> **NOTE:** Correctly fanning out Welcome messages relies on the hub and target
providers storing the `KeyPackageRef` of claimed KeyPackages.

A client which receives a `success` to either an `UpdateRoomResponse` or a
`SubmitMessageResponse` can view this a commitment from the hub provider that
the message will eventually be distributed to the group. The hub is not
expected to forward the client's own message to the client or its provider.
However, the client and its provider need to be prepared to receive the
client's (effectively duplicate) message. This situation can occur during
failover in high availability recovery scenarios.

Clients that are being removed SHOULD receive the corresponding
Commit message, so they can recognize that they have been removed and clean up
their internal state. A removed client might not receive a commit if it was
removed as a malicious or abusive client, or if it obviously deleted.

The response to a FanoutMessage contains no body. The HTTP response code
indicates if the messages in the request were accepted (201 response code), or
if there was an error. The hub need not wait for a response before sending the
next fanout message.

If the hub server does not contain an HTTP 201 response code, then it SHOULD
retry the request, respecting any guidance provided by the server in HTTP header
fields such as Retry-After.  If a follower server receives a duplicate request
to the `/notify` endpoint, in the sense of a request from the same hub server
with the same request body as a previous `/notify` request, then the follower
server MUST return a 201 Accepted response.  In such cases, the follower server
SHOULD process only the first request; subsequent duplicate requests SHOULD be
ignored (despite the success response).

> **NOTE:** These deduplication provisions require follower servers to track
> which request bodies they have received from which hub servers.  Since the
> matching here is byte-exact, it can be done by keeping a rolling list of
> hashes of recent messages.
>
> This byte-exact replay criterion might not be the right deduplication
> strategy.  There might be situations where it is valid for the same hub server
> to send the same payload multiple times, e.g., due to accidental collisions.
>
> If this is a concern, then an explicit transaction ID could be introduced.
> The follower server would still have to keep a list of recently seen
> transaction IDs, but deduplication could be done irrespective of the content
> of request bodies.

## Claim group key information

When a client joins an MLS group without an existing member adding the
client to the MLS group, that is called an external join. This is useful
a) when a new client of an existing user needs to join the groups of all the
user's rooms. It can also be used b) when a client did not have key packages
available but their user is already in the participation list for the
corresponding room, c) when joining an open room, or d) when joining using
an external authentication joining code. In MIMI, external joins are
accomplished by fetching the MLS GroupInfo for a room's MLS group, and then
sending an external commit incorporating the GroupInfo.

The GroupInfoRequest uses the HTTP POST method.

~~~
POST /groupInfo/{roomId}
~~~

The request provides an MLS credential proving the requesting client's real or
pseudonymous identity. This user identity is used by the hub to correlate this
request with the subsequent external commit. The credential may constitute
sufficient permission to authorize providing the GroupInfo and later joining
the group. Alternatively, the request can include an optional opaque joining
code, which the requester could use to prove permission to fetch the GroupInfo,
even if it is not yet a participant.

The request also
provides a signature public key
corresponding to the requester's credential. It also specifies a CipherSuite
which merely needs to be one ciphersuite in common with the hub. It is
needed only to specify the algorithms used to sign the
GroupInfoRequest and GroupInfoResponse.

~~~ tls
struct {
  Protocol protocol;
  select (protocol) {
    case mls10:
      CipherSuite cipher_suite;
      SignaturePublicKey requestingSignatureKey;
      Credential requestingCredential;
      optional opaque joiningCode<V>;
  };
} GroupInfoRequestTBS;

struct {
  Protocol protocol;
  select (protocol) {
    case mls10:
      CipherSuite cipher_suite;
      SignaturePublicKey requestingSignatureKey;
      Credential requestingCredential;
      opaque joiningCode<V>;
      /* SignWithLabel(., "GroupInfoRequestTBS", GroupInfoRequestTBS) */
      opaque signature<V>;
  };
} GroupInfoRequest;
~~~

If successful, the response body contains the GroupInfo and a way
to get the ratchet_tree.

~~~ tls
enum {
  reserved(0),
  success(1),
  notAuthorized(2),
  noSuchRoom(3),
  (255)
} GroupInfoCode;

struct {
  Protocol version;
  GroupInfoCode status;
  select (protocol) {
    case mls10:
      CipherSuite cipher_suite;
      opaque room_id<V>;
      ExternalSender hub_sender;
      GroupInfo groupInfo;   /* without embedded ratchet_tree */
      RatchetTreeOption ratchetTreeOption;
  };
} GroupInfoResponseTBS;

struct {
  Protocol version;
  GroupInfoCode status;
  select (protocol) {
    case mls10:
      CipherSuite cipher_suite;
      opaque room_id<V>;
      ExternalSender hub_sender;
      GroupInfo groupInfo;   /* without embedded ratchet_tree */
      RatchetTreeOption ratchetTreeOption;
      /* SignWithLabel(., "GroupInfoResponseTBS", GroupInfoResponseTBS) */
      opaque signature<V>;
  };
} GroupInfoResponse;
~~~

The semantics of the `GroupInfoCode` are as follows:

- `success` indicates that GroupInfo and ratchet tree was provided as
requested.
- `notAuthorized` indicates that the requester was not authorized to access
the GroupInfo.
- `noSuchRoom` indicates that the requested room does not exist. If the hub
does not want to reveal if a room ID does not exist it can use
`notAuthorized` instead.

> **TODO**: Consider adding additional failure codes/semantics for joining
> codes (ex: code expired, already used, invalid)

**ISSUE**: What security properties are needed to protect a
GroupInfo object in the MIMI context are still under discussion. It is
possible that the requester only needs to prove possession of their private
key. The GroupInfo in another context might be sufficiently sensitive that
it should be encrypted from the end client to the hub provider (unreadable
by the local provider).

## Report abuse

Abuse reports are only sent to the hub provider. They are sent as an HTTP
POST request.

~~~
POST /reportAbuse/{roomId}
~~~

The `reportingUser` optionally contains the identity of the user sending the
`abuseReport`, while the `allegedAbuserUri` contains the URI of the alleged
sender of abusive messages. The `group_id`, `epoch`, and
`allegedAbuserLeafIndex`, all identify the alleged abusing client at a
snapshot in time. The `reasonCode` is reserved to identify the type of abuse,
and the `note` is a UTF8 human-readable string, which can be empty.

> **TODO**: Find a standard taxonomy of reason codes to reference for
> the `AbuseType`. The IANA Messaging Abuse Report Format parameters are
> insufficient.

Finally, abuse reports can optionally contain a handful of (end-to-end
encrypted) abusive messages, and the keys necessary to decrypt them in an
`AbusiveMessage` struct.

~~~ tls
struct {
  /* an application message (wire_format = private_message and */
  /* content_type = application) and the key and nonce to decrypt */
  /* just this single application message */
  MLSMessage applicationMessage;
  opaque key<V>;
  opaque nonce<V>;
} AbusiveMessage;

enum {
  reserved(0),
  (255)
} AbuseType;

struct {
  IdentifierUri reportingUser;
  IdentifierUri allegedAbuserUri;
  opaque group_id<V>;
  uint64 epoch;
  uint32 allegedAbuserLeafIndex;
  AbuseType reasonCode;
  opaque note<V>;
  AbusiveMessage messages<V>;
} AbuseReport;
~~~

There is no response body. The response code only indicates if the abuse report was accepted, not if any specific automated or human action was taken.

# Relation between MIMI state and cryptographic state

## Room state

The state of a room consists of its room ID, its base policy, its
participant list (including the role and participation state of each
participant), and the associated end-to-end protocol state (its MLS group
state) that anchors the room state cryptographically.

While all parties involved in a room agree on the room's state during a
specific epoch, the Hub is the arbiter that decides if a state change is valid,
consistent with the room's then-current policy. All state-changing events are
sent to the Hub and checked for their validity and policy conformance, before
they are forwarded to any follower servers or local clients.

As soon as the Hub accepts an event that changes the room state, its effect is
applied to the room state and future events are validated in the context of that
new state.

The room state is thus changed based on events, even if the MLS proposal
implementing the event was not yet committed by a client. Note that this only
applies to events changing the room state.

## Cryptographic room representation

Each room is represented cryptographically by an MLS group. The Hub that
manages the room also manages the list of group members, i.e. the
list of clients belonging to users currently in the room.

## Proposal-commit paradigm

The MLS protocol follows a proposal-commit paradigm. Any
party involved in a room (follower server, Hub or clients) can send proposals
(e.g. to add/remove/update clients of a user or to re-initialize the group with
different parameters). However, only clients can send commits, which contain all
valid previously sent proposals and apply them to the MLS group state.

The MIMI usage of MLS ensures that the Hub, all follower servers and the clients
of all active participants agree on the group state, which includes the client
list and the key material used for message encryption (although the latter is
only available to clients). Since the group state also includes a copy of the
room state at the time of the most recent commit, it is also covered by the
agreement.

## Authenticating proposals

MLS requires that MLS proposals from the Hub and
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
committed by a MIMI commit.


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

The MIMI protocol incorporates several layers of security.

Individual protocol actions are protected against network attackers with
mutually-authenticated TLS, where the TLS certificates authenticate the
identities that the protocol actors assert at the application layer.

Messages and room state changes are protected end-to-end using MLS.  The
protection is "end-to-end" in the sense that messages sent within the group are
confidentiality-protected against all servers involved in the delivery of those
messages, and in the sense that the authenticity of room state changes is
verified by the end clients involved in the room.  The usage of MLS ensures that
the servers facilitating the exchange cannot read messages in the room or
falsify room state changes, even though they can read the room state change
messages.

Each room has an authorization policy that dictates which protocol actors can
perform which actions in the room.  This policy is enforced by the hub server
for the room.  The actors for whom the policy is being evaluated authenticate
their identities to the hub server using the MLS PublicMessage signed object
format, together with the identity credentials presented in MLS.  This design
means that the hub is trusted to correctly enforce the room's policy, but this
cost is offset by the simplicity of not having multiple policy enforcement points.

# IANA Considerations


--- back

# Acknowledgments
{:numbered="false"}

> **TODO**:
