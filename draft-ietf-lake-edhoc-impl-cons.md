---
v: 3

title: Implementation Considerations for the Lightweight Authenticated Key Exchange (LAKE) Protocol
abbrev: Implementation Considerations for LAKE
docname: draft-ietf-lake-edhoc-impl-cons-latest
cat: info
submissiontype: IETF

ipr: trust200902
area: Security
wg: LAKE Working Group
kw: Internet-Draft

coding: utf-8

author:
 -  name: Marco Tiloca
    org: RISE AB
    street: Isafjordsgatan 22
    city: Kista
    code: SE-16440 Stockholm
    country: Sweden
    email: marco.tiloca@ri.se

normative:
  RFC7252:
  RFC7959:
  RFC8613:
  RFC9528:
  RFC9668:

informative:
  RFC2986:
  RFC5280:
  RFC6960:
  RFC9200:
  I-D.ietf-ace-edhoc-oscore-profile:
  I-D.ietf-core-oscore-key-update:
  I-D.ietf-core-oscore-key-limits:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-lake-authz:
  I-D.ietf-ace-workflow-and-params:
  I-D.ietf-lake-edhoc-psk:
  EDHOC-Fuzzer:
    author:
      -
        ins: K. Sagonas
        name: Konstantinos Sagonas
      -
        ins: T. Typaldos
        name: Thanasis Typaldos
    title: "EDHOC-Fuzzer: An EDHOC Protocol State Fuzzer"
    seriesinfo: "ISSTA 2023: Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis"
    date: 2023-07-13
    target: https://dl.acm.org/doi/10.1145/3597926.3604922

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document provides considerations for guiding the implementation of the Lightweight Authenticated Key Exchange (LAKE) protocol.

--- middle

# Introduction # {#intro}

The specification {{RFC9528}} defines the Lightweight Authenticated Key Exchange (LAKE) protocol, which is especially intended for use in constrained scenarios.

During the development of LAKE, a number of side topics were raised and discussed, as emerging from reviews of the protocol latest design and from implementation activities. These topics were identified as strongly pertaining to the implementation of LAKE rather than to the protocol in itself. Hence, they are not discussed in {{RFC9528}}, which rightly focuses on specifying the actual protocol.

At the same time, implementers of an application using the LAKE protocol or of a "LAKE library" enabling its use cannot simply ignore such topics and will have to take them into account throughout their implementation work.

In order to prevent multiple, independent re-discoveries and assessments of those topics, as well as to facilitate and guide implementation activities, this document collects such topics and discusses them through considerations about the implementation of LAKE. At a high-level, the topics in question are summarized below:

* Handling of completed LAKE sessions when they become invalid and of application keys derived from a LAKE session when those become invalid. This topic is discussed in {{sec-session-handling}}.

* Retention of completed LAKE sessions that are still valid, also in the case that a LAKE error message is received after their completion. This topic is discussed in {{sec-session-retention}}.

* Enforcement of different trust policies, with respect to learning new authentication credentials during an execution of LAKE. This topic is discussed in {{sec-trust-models}}.

* Branched-off side processing of incoming LAKE messages, with particular reference to: i) fetching and validation of authentication credentials; and ii) processing of External Authorization Data (EAD) items, which in turn might play a role in the fetching and validation of authentication credentials. This topic is discussed in {{sec-message-side-processing}}.

* Effectively using LAKE over the Constrained Application Protocol (CoAP) {{RFC7252}} in combination with Block-wise transfers for CoAP {{RFC7959}}, potentially together with the optimized LAKE execution workflow defined in {{RFC9668}}. This topic is discussed in {{sec-block-wise}}.

The scope of the present implementation considerations only includes the use of LAKE with the authentication methods specified in {{Section 3.2 of RFC9528}} and based on public key authentication. A future document can extend the present document and include implementation considerations that consider the use of LAKE with other authentication methods, such as the one defined in {{I-D.ietf-lake-edhoc-psk}} and based on symmetric pre-shared keys.

## Terminology ## {#terminology}

The reader is expected to be familiar with terms and concepts related to the LAKE protocol {{RFC9528}}, (CoAP) {{RFC7252}}, and Block-wise transfers for CoAP {{RFC7959}}.

This document uses the acronym LAKE, expanded to Lightweight Authenticated Key Exchange, to denote the protocol specified as EDHOC in {{RFC9528}}. LAKE is also used in place of EDHOC in descriptive terms such as LAKE message_1 or LAKE EAD item. Identifiers defined literally in {{RFC9528}} or in IANA registries (e.g., EDHOC_Exporter, the EDHOC registries, media types, and URIs) are unchanged.

# Handling of Invalid LAKE Sessions and Application Keys # {#sec-session-handling}

This section considers the most common situation where, given a certain peer, only the application at that peer has visibility and control of both:

* The LAKE sessions at that peer; and

* The application keys for that application at that peer, including the knowledge of whether they have been derived from a LAKE session, i.e., by means of the EDHOC_Exporter interface after the successful completion of an execution of LAKE (see {{Section 4.2 of RFC9528}}).

Building on the above, the following expands on three relevant cases concerning the handling of LAKE sessions and application keys, in the event that any of those becomes invalid.

To provide more concrete guidance, the following considers the case where "application keys" stands for the keying material and parameters that compose a Security Context for the security protocol Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}}, i.e., when specifically those application keys are derived from a LAKE session (see {{Section A.1 of RFC9528}}).

Nevertheless, the same considerations are applicable if LAKE is used to derive other application keys, e.g., when used to key different security protocols than OSCORE or to provide the application with secure values that are bound to a LAKE session.

## LAKE Sessions Become Invalid ## {#sec-session-invalid}

The application at a peer P may have learned that a completed LAKE session S has to be invalidated. When S is marked as invalid, the application at P purges S and deletes each set of application keys (e.g., the OSCORE Security Context) that was generated from S.

Then, the application runs a new execution of the LAKE protocol with the other peer. If the LAKE execution successfully completes, the two peers derive and install a new set of application keys from this latest LAKE session. If the LAKE execution does not successfully complete, the application makes another attempt and runs a new execution of the LAKE protocol with the other peer, provided that the predetermined maximum number of attempts has not been reached yet.

The flowchart in {{fig-flowchart-session-invalid}} shows the handling of a LAKE session that has become invalid.

~~~~~~~~~~~ aasvg
Invalid      Delete the LAKE session
LAKE    ---> and the application keys
session      derived from it

                 |
                 |
                 v

             Rerun LAKE <----------------+
                                         |
                 |                       |
                 |                       | NO
                 v                       |
                         NO
             Has LAKE   ---------> Has the maximum
             succeeded?            number of attempts
                                   been reached?
                 |
                 |                       |
                 | YES                   | YES
                 v                       v

             Derive and               Consider
             install new              rerunning
             application keys         LAKE later
~~~~~~~~~~~
{: #fig-flowchart-session-invalid title="Handling of a LAKE Session that Has Become Invalid." artwork-align="center"}

A LAKE session may have become invalid, for example, because an authentication credential CRED_X has expired, or because the peer P has learned from a trusted source that CRED_X has been revoked. This effectively invalidates CRED_X, and therefore also invalidates any LAKE session where CRED_X was used as authentication credential associated with either peer in the session (i.e., P itself or the other peer). In such a case, the application at P has to additionally delete CRED_X and any stored, corresponding credential identifier.

## Application Keys Become Invalid ## {#sec-keys-invalid}

The application at a peer P may have learned that a set of application keys is not safe to use anymore. When such a set is specifically an OSCORE Security Context, the application may have learned that from the OSCORE library used or from an OSCORE layer that takes part in the communication stack.

A current set SET of application keys shared with another peer can become unsafe to use, for example, due to the following reasons:

* SET has reached a pre-determined expiration time;

* SET has been established to use for an amount of time that is now elapsed, according to enforced application policies; or

* Some elements of SET have been used enough times to approach cryptographic limits that should not be passed, e.g., according to the properties of the security algorithms specifically used. With particular reference to an OSCORE Security Context, such limits are discussed in {{I-D.ietf-core-oscore-key-limits}}.

When this happens, the application at the peer P proceeds as follows:

1. If the following conditions both hold, then the application moves to Step 2. Otherwise, it moves to Step 3.

   * Let us define S as the LAKE session from which the peer P has derived SET or the oldest SET's ancestor set of application keys. Then, since the completion of S with the other peer, the application at P has received from the other peer and successfully verified at least one message protected with any set of application keys derived from S. That is, P has persisted S (see {{Section 5.4.2 of RFC9528}}).

   * The peer P supports a key update protocol, as an alternative to performing a new execution of LAKE with the other peer. When SET is an OSCORE Security Context, the key update protocol supported by the peer P can be KUDOS {{I-D.ietf-core-oscore-key-update}}.

2. The application at P runs the key update protocol mentioned at Step 1 with the other peer, in order to update SET. When SET is an OSCORE Security Context, the application at P can run the key update protocol KUDOS with the other peer.

   If the key update protocol terminates successfully, the updated application keys are installed and no further actions are taken. Otherwise, the application at P moves to Step 3.

3. The application at the peer P performs the following actions:

   * It deletes SET.

   * It deletes the LAKE session from which SET was generated, or from which the oldest SET's ancestor set of application keys was generated before any key update occurred (e.g., by means of the EDHOC_KeyUpdate interface defined in {{Section H of RFC9528}} or other key update methods).

   * It runs a new execution of the LAKE protocol with the other peer. If the LAKE execution successfully completes, the two peers derive and install a new set of application keys from this latest LAKE session. If the LAKE execution does not successfully complete, the application makes another attempt and runs a new execution of the LAKE protocol with the other peer, provided that the predetermined maximum number of attempts has not been reached yet.

The flowchart in {{fig-flowchart-keys-invalid}} shows the handling of a set of application keys that has become invalid. In particular, it assumes such a set to be an OSCORE Security Context and the key update protocol to be KUDOS.

~~~~~~~~~~~ aasvg
Invalid application keys

     |
     |
     |       Handling of invalid application keys
+----|----------------------------------------------------------------+
|    |                                                                |
|    v                                                                |
|                                                                     |
| Are the          NO   Delete the application keys                   |
| application     ----> and the associated LAKE session               |
| keys persisted?                                                     |
|                        ^  ^        |                                |
|                        |  |        |                                |
|   |                    |  |        |     Re-execution of LAKE       |
|   |                    |  |   +----|----------------------------+   |
|   |                    |  |   |    |                            |   |
|   |                    |  |   |    |                            |   |
|   |                    |  |   |    v                            |   |
|   |                    |  |   |                                 |   |
|   |                    |  |   | Rerun LAKE <----------+         |   |
|   |                    |  |   |                       |         |   |
|   | YES                |  |   |    |                  |         |   |
|   v                    |  |   |    |                  | NO      |   |
|                        |  |   |    v                  |         |   |
| Is KUDOS    NO         |  |   |            NO                   |   |
| supported? ------------+  |   | Has LAKE   ----> Has the        |   |
|                           |   | succeeded?       maximum number |   |
|   |                       |   |                  of attempts    |   |
|   | YES                   |   |    |             been reached?  |   |
|   v                       |   |    |                            |   |
|                           |   |    |                  |         |   |
| Run KUDOS                 |   |    | YES              | YES     |   |
|                           |   |    v                  v         |   |
|   |                       |   |                                 |   |
|   |                       |   | Derive and          Consider    |   |
|   v                       |   | install new         rerunning   |   |
|                           |   | application keys    LAKE later  |   |
| Has KUDOS   NO            |   |                                 |   |
| succeeded? ---------------+   +---------------------------------+   |
|                                                                     |
|   |                                                                 |
|   | YES                                                             |
|   v                                                                 |
|                                                                     |
| Install the updated                                                 |
| application keys                                                    |
|                                                                     |
+---------------------------------------------------------------------+
~~~~~~~~~~~
{: #fig-flowchart-keys-invalid title="Handling of a Set of Application Keys that Has Become Invalid." artwork-align="center"}

## Application Keys or Bound Access Rights Become Invalid ## {#sec-keys-token-invalid}

The following considers two peers that use the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}} and specifically the profile of ACE defined in {{I-D.ietf-ace-edhoc-oscore-profile}}. One of the two peers acts as an ACE resource server (RS). The other peer acts as an ACE client (C) and requests an access token from an ACE authorization server (AS) that is in a trust relationship with the RS. The access token specifies the access rights of C for accessing protected resources hosted at the RS.

Per the considered profile of ACE, the two peers run LAKE to derive an OSCORE Security Context as their shared set of application keys (see {{Section A.1 of RFC9528}}). During the LAKE execution, the peer acting as the ACE client uploads the access token at the RS, by means of an EAD item included in a LAKE message (see {{Section 3.8 of RFC9528}}). At the RS, the access token is bound to the successfully completed LAKE session and to the established OSCORE Security Context, which is used to protect the subsequent communications between the two peers.

Later on, the application at one of the two peers P may have learned that the established OSCORE Security Context CTX is not safe to use anymore, e.g., from the OSCORE library used or from an OSCORE layer that takes part in the communication stack. The reasons that make CTX not safe to use anymore are the same ones discussed in {{sec-keys-invalid}} when considering a set of application keys in general, plus the event that the access token bound to CTX becomes invalid (e.g., it has expired or it has been revoked).

When this happens, the application at the peer P proceeds as follows. The handling below builds on and extends the handling defined in {{sec-keys-invalid}}, by additionally considering the event where the access token becomes invalid.

1. If the following conditions both hold, then the application moves to Step 2. Otherwise, it moves to Step 3.

   * The access token is still believed to be valid. That is, it has not expired yet and the peer P is not aware that it has been revoked.

   * Let us define S as the LAKE session from which the peer P has derived CTX or the oldest CTX's ancestor OSCORE Security Context. Then, since the completion of S with the other peer, the application at P has received from the other peer and successfully verified at least one message protected with any set of application keys derived from S. That is, P has persisted S (see {{Section 5.4.2 of RFC9528}}).

2. If the peer P supports the key update protocol KUDOS {{I-D.ietf-core-oscore-key-update}}, then P runs KUDOS with the other peer, in order to update CTX. If the execution of KUDOS terminates successfully, the updated OSCORE Security Context is installed and no further actions are taken.

   If the execution of KUDOS does not terminate successfully or if the peer P does not support KUDOS altogether, then the application at P moves to Step 3.

3. The application at the peer P performs the following actions:

   * If the access token is not believed to be valid anymore, the peer P deletes all the LAKE sessions associated with the access token as well as the OSCORE Security Context derived from each of those sessions. Note that, in the considered profile of ACE, an access token is associated with at most one LAKE session (see {{Section 4.2 of I-D.ietf-ace-edhoc-oscore-profile}}).

     In the case that the peer P acts as the ACE client, P obtains from the ACE AS a new access token to upload at the other peer.

     Finally, the application at P moves to Step 4.

   * If the access token is valid while the OSCORE Security Context CTX is not, then the peer P deletes CTX.

     After that, the peer P deletes the LAKE session from which CTX was generated, or from which the oldest CTX's ancestor OSCORE Security Context was generated before any key update occurred (e.g., by means of KUDOS or other key update methods).

     Finally, the application at P moves to Step 4.

4. The peer P runs a new execution of the LAKE protocol with the other peer. If the LAKE execution successfully completes, the two peers derive and install a new OSCORE Security Context from this latest LAKE session. At the RS, the access token is bound to this latest LAKE session and the newly established OSCORE Security Context.

   If the LAKE execution does not successfully complete, the peer P makes another attempt and runs a new execution of the LAKE protocol with the other peer, provided that the predetermined maximum number of attempts has not been reached yet.

   Per the considered profile of ACE, the peer acting as the ACE client takes the first step to start an execution of LAKE with the other peer, i.e., as LAKE Initiator (Responder) according to the LAKE forward (reverse) message flow (see {{Section A.2 of RFC9528}}).

The flowchart in {{fig-flowchart-keys-token-invalid}} shows the handling of an access token or of a set of application keys that have become invalid, when using the profile of ACE defined in {{I-D.ietf-ace-edhoc-oscore-profile}}. Note that some details within the frame "Handling of invalid application keys" are replaced by ellipses, as they are identical to what is shown in {{fig-flowchart-keys-invalid}}.

~~~~~~~~~~~ aasvg
Invalid access token or
invalid application keys

     |
     |
     v
                NO
Is the         --------> Delete the associated -----> Is this peer
access token             LAKE sessions and            the ACE client?
still believed           the application keys
to be valid?             derived from those               |
                                                          |     NO
                                                          +--------+
     |                                                    |        |
     |                                                    |        |
     |                                                    | YES    |
     |                                                    v        |
     | YES                                                         |
     v                                               Obtain a new  |
                                                     access token  |
The application keys                                 to upload at  |
are not valid anymore                                the ACE RS    |
                                                                   |
     |                                                    |        |
     |                                                    |        |
     |       Handling of invalid application keys         |        |
+----|----------------------------------------------------|--------|--+
|    |                                                    |        |  |
|    v                                                    |        |  |
|                                                         |        |  |
| Are the          NO   Delete the application keys       |        |  |
| application     ----> and the associated LAKE session   |        |  |
| keys persisted?                                         |        |  |
|                                    |                    |        |  |
|    |                               |                    |        |  |
|    |                               v                    v        |  |
|    |                               o<-------------------o<-------+  |
|    |                               |                                |
|    |                               |                                |
|    | YES                           |     Re-execution of LAKE       |
|    v                          +----|----------------------------+   |
|                               |    |                            |   |
|                               |    v                            |   |
|   ...                         |                                 |   |
|                               | Rerun LAKE  <--- ...            |   |
|                               |                                 |   |
|                               |    |                            |   |
|                               |    |                            |   |
|   ...                         |    v                            |   |
|                               |                                 |   |
|                               |   ...                           |   |
|                               |                                 |   |
|   ...                         +---------------------------------+   |
|                                                                     |
+---------------------------------------------------------------------+
~~~~~~~~~~~
{: #fig-flowchart-keys-token-invalid title="Handling of an Access Token or of a Set of Application Keys that Have Become Invalid." artwork-align="center"}

# Retention of Completed LAKE Sessions # {#sec-session-retention}

After successfully completing a LAKE session S and potentially using the EDHOC_Exporter interface to derive keying material from S, a LAKE peer is expected to store and retain the latest state of S over time.

The latest state of S can be stored in volatile memory, although a reboot would result in a loss of that state and the need to rerun LAKE with the other peer that participated in the session S. When it is supported, storing in non-volatile memory is a more robust alternative. Note that requirements to fulfill for persistently storing PRK_out or derived application keys are defined in {{Sections 5.4.2 and 5.4.3 of RFC9528}}.

Retaining the state of S ensures that it is possible to:

* Update S by updating its associated PRK_out in a more efficient way than rerunning LAKE, e.g., by using the EDHOC_KeyUpdate function defined in {{Section H of RFC9528}}.

* Use the EDHOC_Exporter interface for late derivations of keying material from S that cannot be performed shortly after the session completion or according to a predictable schedule.

Absent application policies defining more restrictive lifetimes, the peer is expected to retain the latest state of S in its local storage until:

* S has to be deleted due to reasons discussed in {{sec-session-handling}}; or

* S has to be deleted due to memory limitations, in which case the peer ought to delete the oldest completed LAKE session first.

## Handling of Incoming LAKE Error Messages

{{Section 5.1 of RFC9528}} defines that a LAKE session is completed after having successfully processed the last message, i.e., message_3 or message_4, depending on the application profile used (see {{Section 3.9 of RFC9528}}). It follows that:

* When a peer sends the last message in a session, that peer completes the session after successfully building and sending such message.

* When a peer receives the last message in a session, that peer completes the session after receiving and successfully processing such message.

Furthermore, {{Section 6 of RFC9528}} defines LAKE error messages and the processing associated with the initial set of error codes. According to {{Section 5.1 of RFC9528}}, after a LAKE session is completed, no LAKE error messages are sent and the LAKE session output may be maintained even if LAKE error messages are received.

That is, an implementation has a lot of latitude about handling incoming LAKE error messages that pertain to a completed LAKE session.

In general, a safe approach simply consists in aborting the completed LAKE session, thereby deleting the corresponding output such as derived application keys. If the reception of LAKE error messages at a given peer P is still plausible, this is actually an appropriate course of action for P. In particular, this applies if P is the sender of the last message and therefore could receive a LAKE error message as a follow-up from the other peer that rejected the last message.

However, there are indeed cases where it is not plausible anymore to receive LAKE error messages pertaining to a completed LAKE session. Such LAKE error messages can be safely ignored as irrelevant and potentially resulting from an attack, thereby preserving the LAKE session output such as derived application keys. In particular, it is possible to safely ignore incoming LAKE error messages for:

* The peer that receives and successfully processes the last message in the session.

* The peer that successfully builds and sends the last message in the session, after it has received and successfully verified a message from the other peer that is protected with an application key derived from the session.

### Detailed Guidance for CoAP and OSCORE

The rest of this section considers the specific case where:

* "application keys" stands for the keying material and parameters that compose an OSCORE Security Context {{RFC8613}}, i.e., when specifically those application keys are derived from a LAKE session (see {{Section A.1 of RFC9528}}).

* LAKE messages are transferred over CoAP {{RFC7252}} using the forward message flow (see {{Section A.2 of RFC9528}}), i.e., the LAKE Responder acts as a CoAP server and the LAKE Initiator acts as a CoAP client.

Building on the above, the following holds for the LAKE Responder.

* If LAKE message_3 is the last message in the LAKE session (i.e., LAKE message_4 is not used), the Responder completes the session after receiving and successfully processing the incoming LAKE message_3.

  Consequently, the Responder can safely set the LAKE session to ignore any incoming LAKE error message pertaining to the session from then on, thereby preserving the OSCORE Security Context derived from the session.

* If LAKE message_4 is used and thus is the last message in the LAKE session, the Responder completes the session after successfully building and sending LAKE message_4.

  After that, it remains generally appropriate for the Responder to abort the LAKE session in the event that the Responder receives a LAKE error message pertaining to the session. In particular, the LAKE error message might have been legitimately sent by the Initiator that failed to process LAKE message_4.

  However, the Responder can safely set the LAKE session to ignore any incoming LAKE error message pertaining to the session from then on, after successfully processing an incoming OSCORE-protected message received from the Initiator. Similarly to the case previously discussed, this preserves the OSCORE Security Context derived from the session, in the event that the Responder receives LAKE error messages.

Also building on the above, the following holds for the LAKE Initiator.

* If LAKE message_4 is used and thus is the last message in the LAKE session, the Initiator completes the session after successfully processing the incoming LAKE message_4.

  Consequently, the Initiator can safely set the LAKE session to ignore any incoming LAKE error message pertaining to the session from then on, thereby preserving the OSCORE Security Context derived from the session.

* If LAKE message_3 is the last message in the LAKE session (i.e., LAKE message_4 is not used), the Initiator completes the session after successfully building and sending LAKE message_3.

  After that, it remains generally appropriate for the Initiator to abort the LAKE session in the event that the Initiator receives a LAKE error message pertaining to the session. In particular, the LAKE error message might have been legitimately sent by the Responder that failed to process LAKE message_3.

  If an active adversary injects a LAKE error message intended to the Initiator and pertaining to the LAKE session, the Initiator would effectively receive and process that message only during a specific time interval, i.e., from when the Initiator sends LAKE message_3 until when the Initiator frees up the CoAP Token value used in the CoAP request message that conveyed LAKE message_3.

  However, the Initiator can safely set the LAKE session to ignore any incoming LAKE error message pertaining to the session, after successfully processing an incoming OSCORE-protected message received from the Responder. Similarly to the case previously discussed, this preserves the OSCORE Security Context derived from the session, in the event that the Initiator receives LAKE error messages.

Following the reception and successful verification for the first time of an OSCORE-protected message using the OSCORE Security Context derived from a completed LAKE session, a recipient LAKE peer has different ways for setting the session to ignore pertaining LAKE error messages from then on.

Some approaches can be easier and more appealing to use than others, depending on the specific LAKE implementation and its integration with the communication stack. As an example, the following describes two possible approaches, which are applicable to either message flow and also when other protocols than CoAP are used to transfer LAKE messages:

* The OSCORE library used or an OSCORE layer that takes part in the communication stack can be aware that an OSCORE Security Context CTX was derived from a LAKE session S.

  In such a case, after receiving and successfully verifying for the first time an OSCORE-protected message using CTX, the OSCORE library/layer on the recipient LAKE peer can effectively set the LAKE session S to ignore any incoming LAKE error message pertaining to the session from then on.

* When receiving a LAKE error message pertaining to a completed LAKE session, LAKE can check whether the session is set to ignore pertaining LAKE error messages. If that is the case, the received LAKE error message is ignored.

  Otherwise, LAKE checks whether the OSCORE Security Context CTX derived from the LAKE session has been used at least once for successfully verifying an incoming OSCORE-protected message from the other LAKE peer (e.g., by checking the Replay Window within the Recipient Context of CTX).

  In the case that CTX has not been used yet, the received LAKE error message is processed as usual, i.e., the LAKE session is aborted and CTX is deleted. Instead, in the case that CTX has been used at least once for successfully verifying an incoming OSCORE-protected message from the other LAKE peer, the LAKE error message is ignored and LAKE sets the LAKE session to ignore pertaining LAKE error messages from then on.

# Trust Policies for Learning New Authentication Credentials # {#sec-trust-models}

A peer P relies on authentication credentials associated with other peers, in order to authenticate those peers when running LAKE with them.

There are different ways for P to acquire an authentication credential CRED associated with another peer. For example, CRED can be supplied to P out-of-band by a trusted provider.

Alternatively, CRED can be specified by the other peer during the LAKE execution with P. This can rely on LAKE message_2 or message_3, whose respective ID_CRED_R and ID_CRED_I field can specify CRED by value, or instead a URI or other external reference where CRED can be retrieved from (see {{Section 3.5.3 of RFC9528}}).

Also during the LAKE execution, an EAD field might include an EAD item that specifies CRED by value, or instead a URI or other external reference where CRED can be retrieved from. This is the case, e.g., for an EAD item specified by the profile of the ACE framework defined in {{I-D.ietf-ace-edhoc-oscore-profile}}. In particular, the EAD item is used for transporting an access token, which in turn specifies by value or by reference the public authentication credential associated with the LAKE peer acting as the ACE client.

When obtaining a new credential CRED, the peer P has to validate it before storing it. The validation steps to perform depend on the specific type of CRED (e.g., a public key certificate {{RFC5280}}{{I-D.ietf-cose-cbor-encoded-cert}}) and can rely on (the authentication credential associated with) a trusted third party acting as a trust anchor.

Upon retrieving a new CRED through the processing of a received LAKE message and following the successful validation of CRED, the peer P stores CRED only if it assesses CRED to also be (provisionally) trusted, while it must not store CRED otherwise. A narrow exception is discussed in {{sec-unauth-operation}}.

When processing a received LAKE message M that specifies an authentication credential CRED, the peer P can enforce one of the trust policies LEARNING and NO-LEARNING specified in {{sec-policy-learning}} and {{sec-policy-no-learning}}, in order to determine whether to trust CRED.

{{tab-trust-policies}} provides a summary of the behavior of P about accepting CRED, for different trust policies. Provisional trust on CRED has to be later confirmed, e.g., by information that vouches for CRED and is conveyed within a LAKE message received during the LAKE session (e.g., transported by an EAD item).

| Trust policy                                          | CRED is not new (already stored)          | CRED is new<br>(not already stored)                     |
+-------------------------------------------------------|-------------------------------------------|---------------------------------------------------------|
| LEARNING policy                                       | Accept,<br>if still valid<br>and trusted. | Accept, if valid and therefore (provisionally) trusted. |
+-------------------------------------------------------|-------------------------------------------|---------------------------------------------------------|
| NO-LEARNING policy, without <br> acceptable exception | Accept,<br>if still valid<br>and trusted. | Do not accept.                                          |
+-------------------------------------------------------|-------------------------------------------|---------------------------------------------------------|
| NO-LEARNING policy, with <br> acceptable exception    | Accept,<br>if still valid<br>and trusted. | Accept, if valid and<br>(provisionally) trusted.        |
+-------------------------------------------------------|-------------------------------------------|---------------------------------------------------------|
{: #tab-trust-policies title="Summary about Accepting the Authentication Credential CRED Associated with the Other Peer in a LAKE Session, for Different Trust Policies." align="center"}

Irrespective of the adopted trust policy, P actually uses CRED only if it is determined to be fine to use in the context of the ongoing LAKE session, also depending on the specific identity of the other peer (see {{Sections 3.5 and D.2 of RFC9528}}). If this is not the case, P aborts the LAKE session with the other peer.

If P stores CRED, then P will consider CRED as valid and trusted until:

* CRED becomes invalid, e.g., because it expires or because P gains knowledge that it has been revoked; or

* CRED becomes non-trusted, e.g., because P originally assessed CRED to be provisionally trusted, and later on failed to obtain an expected final confirmation of trust.

P must delete CRED from its local storage if CRED becomes invalid or non-trusted.

When storing CRED, the peer P should generate the authentication credential identifier(s) corresponding to CRED and store them as associated with CRED. For example, if CRED is a public key certificate, an identifier of CRED can be the hash of the certificate. In general, P should generate and associate with CRED one corresponding identifier for each type of authentication credential identifier that P supports and that is compatible with CRED.

In future executions of LAKE with the other peer associated with CRED, this allows such other peer to specify CRED by reference, e.g., by indicating its credential identifier as ID_CRED_R/ID_CRED_I in the LAKE message_2 or message_3 addressed to the peer P. In turn, this allows P to retrieve CRED from its local storage.

## Trust Policy LEARNING # {#sec-policy-learning}

When enforcing the LEARNING policy, the peer P trusts CRED even if P is not already storing CRED at message reception time.

That is, upon receiving M, the peer P performs the following steps.

1. P retrieves CRED, as specified by reference or by value in the ID_CRED_I/ID_CRED_R field of M or in the value of an EAD item of M.

2. P checks whether CRED is already being stored and if it is still valid and trusted. In such a case, P trusts CRED and can continue the LAKE execution. Otherwise, P moves to Step 3.

3. P attempts to validate CRED. If the validation process is not successful, P aborts the LAKE session with the other peer. Otherwise, P trusts and stores CRED, and can continue the LAKE execution.

## Trust Policy NO-LEARNING # {#sec-policy-no-learning}

When enforcing the NO-LEARNING policy, the peer P trusts CRED only if P is already storing CRED at message reception time, unless in cases where situation-specific exceptions apply and are deliberately enforced (see below).

That is, upon receiving M, the peer P continues the execution of LAKE only if both the following conditions hold:

* P currently stores CRED, as specified by reference or by value in the ID_CRED_I/ID_CRED_R field of M or in the value of an EAD item of M; and

* CRED is still valid (i.e., P believes CRED to not be expired or revoked) and trusted.

Exceptions may apply and be actually enforced in cases where, during a LAKE execution, P obtains additional information that allows it to trust and successfully validate CRED, even though P was not already storing CRED when receiving M.

Such exceptions typically rely on a trusted party that vouches for CRED, e.g., in the cases discussed in {{sec-trust-models-specific}}. From the point of view of the peer P, the trusted party might have been involved in the background, so that the vouching information about CRED is conveyed within a LAKE message received during the LAKE session (e.g., transported by an EAD item). Alternatively, P might directly interact with the trusted party for retrieving the vouching information about CRED, e.g., after having received M and before continuing the LAKE execution.

If the peer P admits such an exception and actually enforces it on an authentication credential CRED, then P effectively handles CRED according to the trust policy "LEARNING" specified in {{sec-policy-learning}}. When doing so, P still attempts to validate CRED, and it aborts the LAKE session if the validation process is not successful.

## Enforcement of Trust Policies in Specific Scenarios # {#sec-trust-models-specific}

The following subsections discuss how a LAKE peer enforces the trust policies LEARNING and NO-LEARNING in specific scenarios.

### In the ACE Framework # {#sec-trust-models-ace-prof}

As discussed in {{sec-keys-token-invalid}}, two LAKE peers can be using the ACE framework {{RFC9200}} and specifically the profile of ACE defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

In this case, one of the two LAKE peers, namely PEER_RS, acts as the ACE resource server (RS). Instead, the other LAKE peer, namely PEER_C, acts as the ACE client and obtains from an ACE authorization server (AS) an access token for accessing protected resources at PEER_RS. The AS and PEER_RS are in a trust relationship.

Together with other information, the access token specifies (by value or by reference) the public authentication credential AUTH_CRED_C associated with PEER_C that PEER_C is going to use when running LAKE with PEER_RS. Note that AUTH_CRED_C will be used as either CRED_I or CRED_R in LAKE, depending on whether the two peers use the LAKE forward message flow (i.e., PEER_C is the LAKE Initiator) or the LAKE reverse message flow (i.e., PEER_C is the LAKE Responder), respectively (see {{Section A.2 of RFC9528}}).

When the AS issues the first access token that specifies AUTH_CRED_C and is intended to be uploaded to PEER_RS, it is expected that the access token specifies AUTH_CRED_C by value and that PEER_RS is not currently storing AUTH_CRED_C, but instead will obtain it and learn it upon receiving the access token.

Although the AS can upload the access token to PEER_RS on behalf of PEER_C as per the alternative SDC workflow defined in {{I-D.ietf-ace-workflow-and-params}}, the access token is typically uploaded to PEER_RS by PEER_C through a dedicated EAD item, when running LAKE with PEER_RS. The specific LAKE message that includes the EAD item conveying the access token depends on whether the two peers use the LAKE forward message flow or the LAKE reverse message flow.

Consequently, PEER_RS has to learn AUTH_CRED_C as a new authentication credential during a LAKE session with PEER_C.

At least for its LAKE resource used for exchanging the LAKE messages of the LAKE session in question, this requires PEER_RS to:

* Enforce the trust policy "LEARNING"; or

* If enforcing the trust policy "NO-LEARNING", additionally enforce an overriding exception when an incoming LAKE message includes an EAD item specifying a valid access token issued by a trusted AS.

  That is, through a successful verification of the access token, PEER_RS is able to trust AUTH_CRED_C (if found valid), even though it was not already storing AUTH_CRED_C when receiving the LAKE message with the EAD item.

### In the ELA Procedure # {#sec-trust-models-ela}

When the execution of LAKE embeds the ELA procedure for lightweight authorization defined in {{I-D.ietf-lake-authz}}, the LAKE peer U receives a LAKE message_2 (message_3) where ID_CRED_R (ID_CRED_I) specifies by value the authentication credential CRED associated with the other peer V.

Furthermore, a LAKE message sent to U includes an EAD item, which specifies a voucher issued by a trusted enrollment server W. The voucher is an assertion to U that W has authorized V and has endorsed CRED.

The specific LAKE message that includes the EAD item conveying the voucher depends on whether U and V use the LAKE forward message flow (i.e., U is the LAKE Initiator) or the LAKE reverse message flow (i.e., U is the LAKE Responder). In particular:

* When using the LAKE forward message flow, the EAD item is included in LAKE message_4, thereby endorsing CRED that was specified by ID_CRED_R in the previous LAKE message_2.

  Since it is indeed expected that U is not already storing CRED upon receiving LAKE message_2, U can at best provisionally trust CRED (if found valid) when retrieving it from LAKE message_2.

* When using the LAKE reverse message flow, the EAD item is included in LAKE message_3, thereby endorsing CRED that is specified by ID_CRED_I in the same LAKE message.

In either case, through a successful verification of the voucher, U is able to ultimately trust CRED (if found valid), even though U was not already storing CRED upon receiving the LAKE message specifying CRED.

Therefore, if U enforces the trust policy "NO-LEARNING", it can additionally enforce an overriding exception as below:

* When using the LAKE forward message flow, the exception is enforced when processing a LAKE message_2, and it is raised by the intention of using the ELA procedure. That is, U intends to proceed with sending a consistent LAKE message_3 that indicates the wish to obtain a voucher issued by W.

  At that point in time, the authentication credential CRED is only provisionally trusted (if found valid), with the expectation to receive a LAKE message_4 in the same LAKE session, conveying a valid voucher issued by W and thus confirming that CRED can be ultimately trusted.

* When using the LAKE reverse message flow, the exception is enforced when processing a LAKE message_3, and it is raised by the LAKE message_3 including an EAD item that conveys a valid voucher issued by W, thus confirming that CRED can be ultimately trusted.

## Unauthenticated Operation {#sec-unauth-operation}

When a peer P runs LAKE with another peer, it could be the case that P retrieves a new CRED of that other peer through the processing of a received LAKE message.

A very specific use of LAKE described in {{Section D.5 of RFC9528}} allows P to temporarily accept the other peer as an unknown or not-yet-trusted endpoint, and to establish a trust relationship with the other peer later on. To this end, P can take different approaches: For example, CRED is verified out-of-band at a later stage, or a LAKE session key is bound to an identity out-of-band at a later stage.

# Side Processing of Incoming LAKE Messages # {#sec-message-side-processing}

This section describes a possible approach that LAKE peers can use upon receiving LAKE messages, in order to fetch/validate authentication credentials and to process EAD items.

The transport mechanism provided by LAKE for conveying EAD items is defined in {{Section 3.8 of RFC9528}}. In particular, a LAKE message_x can include one dedicated EAD field EAD_x, for x = 1, 2, 3, or 4. In turn, an EAD field can include one or more EAD items.

As per {{Section 9.1 of RFC9528}}, specifications defining those EAD items have to set the ground for "agreeing on the surrounding context and the meaning of the information passed to and from the application".

The approach described in this section aims to help implementers navigate the surrounding context mentioned above, irrespective of the specific EAD items conveyed in the LAKE messages. In particular, the described approach takes into account the following two points:

* Fetching and validating the authentication credential associated with the other peer rely on ID_CRED_I in LAKE message_2, or on ID_CRED_R in LAKE message_3, or on the value of an EAD item. When this occurs upon receiving LAKE message_2 or message_3, the decryption of the LAKE message has to be completed first.

  Validating the authentication credential or assessing whether it is trusted might depend on using the value of an EAD item, which in turn has to be validated first.

* It is possible that some EAD items can be processed only after having successfully verified the LAKE message, i.e., after a successful verification of the Signature_or_MAC field in LAKE message_2 or message_3.

  For instance, an EAD item within the EAD_3 field of LAKE message_3 might contain a Certificate Signing Request (CSR) {{RFC2986}}. Hence, such an EAD item can be processed only once the recipient peer has attained proof that the other peer possesses its own private key.

In order to conveniently handle such processing, the application can prepare in advance a "side-processor object" (SPO), which takes care of the operations above during the LAKE execution.

In particular, the application provides LAKE with the SPO before starting a LAKE execution, during which LAKE will temporarily transfer control to the SPO at the right point in time, in order to perform the required side-processing of an incoming LAKE message.

The following subsections provide a high-level description of the SPO in terms of expected features and services. Building on that, {{sec-example-spo}} provides a detailed example of how the SPO can be implemented.

## Instructing the Side-Processor Object # {#sec-instructing-spo}

From a high-level perspective, the application instructs the SPO about:

* How to prepare any EAD item such that: it has to be included in the EAD field of an outgoing LAKE message, potentially together with other EAD items; and it is independent of the processing of other EAD items included in incoming LAKE messages. This includes, for instance, the preparation of padding EAD items (see {{Section 3.8.1 of RFC9528}}).

* The list of one or more EAD items that are expected to be present within the dedicated EAD field of specific, incoming LAKE messages during the LAKE session. This takes into account, for instance, external security applications that will be integrated in the LAKE session (e.g., see {{I-D.ietf-lake-authz}}).

  Throughout the LAKE session, the SPO keeps such a list of expected EAD items up-to-date. This takes into account, for instance, external security applications that have been run integrated in the LAKE session, the current status of the session, as well as the LAKE messages that have been exchanged during the session and the outcome of their processing.

## Invoking the Side-Processor Object # {#sec-invoking-spo}

At the right point in time during the processing of an incoming LAKE message M at the peer P, LAKE invokes the SPO. In particular:

* If M is LAKE message_1, LAKE invokes the SPO after the Responder peer has successfully decoded M and accepted the selected cipher suite.

* If M is LAKE message_2 or message_3, LAKE invokes the SPO:

  * Right after M has been decrypted and before starting its verification, i.e., before verifying the Signature_or_MAC field of M; and

  * Right after M has been successfully verified, i.e., after having verified the Signature_or_MAC field of M.

* If M is LAKE message_4, LAKE invokes the SPO after the Initiator peer has successfully decrypted M.

When invoking the SPO for processing message M, LAKE provides the SPO with the following input:

* When M is LAKE message_2 or message_3, an indication of whether this invocation is happening before or after the message verification (i.e., before or after having verified the Signature_or_MAC field).

* The full set of information related to the current LAKE session. This especially includes the selected cipher suite and the ephemeral Diffie-Hellman public keys G_X and G_Y that the two peers have exchanged in the LAKE session.

* The authentication credentials that the peer P stores as associated with other peers.

* All the decrypted information elements retrieved from M.

* The EAD items included in M.

   - Note that LAKE could do some preliminary work on M before invoking the SPO, in order to provide the SPO only with actually relevant EAD items. This requires the application to additionally provide LAKE with the ead_labels of the EAD items that the peer P recognizes (see {{Section 3.8 of RFC9528}}).

     With such information available, LAKE can early abort the current session if M includes any EAD item which is both critical and not recognized by the peer P.

     If no such EAD items are found, LAKE can remove any padding EAD item (see {{Section 3.8.1 of RFC9528}}) and any EAD item which is neither critical nor recognized (since the SPO is going to ignore it anyway). This results in LAKE providing the SPO only with EAD items that will be recognized and that require actual processing.

   - Note that, after having processed the EAD items, the SPO might actually need to store them throughout the whole LAKE execution, e.g., in order to refer to them also when processing later LAKE messages in the current LAKE session.

The SPO performs the following tasks on the incoming message M:

* The SPO checks whether M does not include an EAD item whose presence was expected, based on the related list maintained throughout the LAKE session. If such an EAD item is absent, the SPO can come to an early determination about whether and how to proceed with the processing of M.

  In particular, if an EAD item is absent although its presence was strictly required, then the SPO can early abort the LAKE session, thereby avoiding potentially costly operations (e.g., the retrieval and validation of the authentication credential associated with the other peer).

* The SPO fetches and/or validates the authentication credential CRED associated with the other peer, based on a dedicated EAD item of M or on the ID_CRED field of M (for LAKE message_2 or message_3). Furthermore, the SPO assesses whether CRED can be trusted, in accordance with the trust policy used (see {{sec-trust-models}}).

  {{sec-consistency-checks-auth-creds}} describes special handling of incoming LAKE messages, as to consistency checks concerning authentication credentials in particular situations.

* The SPO processes the EAD items conveyed in the EAD field of M.

* The SPO stores the results of the performed operations and makes such results available to the application.

When the SPO has completed its side processing and transfers control back to LAKE, the SPO provides LAKE with the produced EAD items to include in the EAD field of the next outgoing LAKE message. The production of such EAD items can be triggered, for example, by:

* The completed consumption of EAD items that were included in M.

* The completed execution of instructions that the SPO received from the application, concerning EAD items to produce irrespective of other EAD items included in M.

The flowchart in {{fig-flowchart-spo-high-level}} shows the high-level interactions between the core LAKE processing and the SPO, with particular reference to an incoming LAKE message_2 or message_3.

~~~~~~~~~~~ aasvg
Incoming
LAKE message_X
(X = 2 or 3)

      |
      |
+-----|---------------------------------------------------------------+
|     |                                          Core LAKE processing |
|     v                                                               |
| +-----------+    +----------------+            +----------------+   |
| | Decode    |--->| Retrieve the   |            | Advance the    |   |
| | message_X |    | protocol state |            | protocol state |   |
| +-----------+    +----------------+            +----------------+   |
|                    |                             ^                  |
|                    |                             |                  |
|                    v                             |                  |
|       +--------------+   +--------------------+  |                  |
|       | Decrypt      |   | Verify             |  |                  |
|       | CIPHERTEXT_X |   | Signature_or_MAC_X |  |                  |
|       +--------------+   +--------------------+  |                  |
|                |           ^           |         |                  |
|                |           |           |         |                  |
+----------------|-----------|-----------|---------|------------------+
                 |           |           |         |
                 |           |           |         | ................
          Divert |      Get  |    Divert |    Get  | : EAD items    :
                 |      back |           |    back | : for the next :
                 |           |           |         | : LAKE message :
                 |           |           |         | :..............:
                 |           |           |         |
+----------------|-----------|-----------|---------|------------------+
|                |           |           |         |                  |
|                v           |           v         |                  |
| +---------------------------+     +-----------------------------+   |
| | a) Check whether expected |     | Processing of               |   |
| |    EAD items are absent   |     | post-verification EAD items |   |
| | b) Retrieval and          |     +-----------------------o-----+   |
| |    validation of CRED_X;  |                             |         |
| | c) Trust assessment       o-------- Shared state -------o         |
| |    of CRED_X;             |                                       |
| | d) Processing of          |        ......................         |
| |    pre-verification       |        : Instructions about :         |
| |    EAD items              |        : EAD items to       :         |
| |                           |        : unconditionally    :         |
| | - (b) and (d) might have  |        : produce for the    :         |
| |   to occur in parallel    |        : next LAKE message  :         |
| | - (c) depends on the      |        :....................:         |
| |   trust policy used       |                                       |
| +---------------------------+                                       |
|                                         Side-Processor Object (SPO) |
+---------------------------------------------------------------------+
~~~~~~~~~~~
{: #fig-flowchart-spo-high-level title="High-Level Interaction Between the Core LAKE Processing and the Side-Processor Object (SPO), for Incoming LAKE message_2 and message_3." artwork-align="center"}

## After a LAKE Session # {#sec-after-lake-spo}

After completing the LAKE execution, control is transferred back to the application. In particular, the application is provided with the overall outcome of the LAKE execution (i.e., successful completion or failure), together with possible specific results produced by the SPO throughout the LAKE execution (e.g., due to the processing of EAD items).

After that, the application might need to perform follow-up actions, depending on the outcome of the LAKE execution. For example, the SPO might have preliminarily filled application-level data structures, as a result of processing EAD items. In the case of a successful LAKE execution, the application might need to finalize such data structures. Instead, in the case of an unsuccessful LAKE execution, the application might need to clean-up or amend such data structures, or even roll back what the SPO did, unless the SPO already performed such actions before control was transferred back to the application.

## Consistency Checks of Authentication Credentials from ID\_CRED and EAD Items ## {#sec-consistency-checks-auth-creds}

Typically, a LAKE peer specifies its associated authentication credential (by value or by reference) only in the ID_CRED field of LAKE message_2 (if acting as Responder) or LAKE message_3 (if acting as Initiator).

In addition to that, there may be cases where a LAKE peer provides the authentication credential also in an EAD item. In particular, such an EAD item can specify a cryptographically protected "envelope" (by value or by reference), which in turn specifies the authentication credential (by value or by reference).

A case in point is the profile of the ACE framework defined in {{I-D.ietf-ace-edhoc-oscore-profile}}, where the envelope in question is an access token issued to the ACE client. In such a case, the ACE client can rely on an EAD item specifying the access token, which in turn specifies the authentication credential (by value or by reference) associated with the client.

During a LAKE session, a LAKE peer P1 might therefore receive the authentication credential CRED associated with the other LAKE peer P2 as specified by two items:

* ITEM_A: the ID_CRED field specifying CRED. If P2 acts as the Initiator (Responder), then ITEM_A is the ID_CRED_I (ID_CRED_R) field.

* ITEM_B: the envelope specified in an EAD item within a LAKE message sent by P2.

As part of the process where P1 validates CRED during the LAKE session, P1 must check that both ITEM_A and ITEM_B specify the same authentication credential, and it must abort the LAKE session if such a consistency check fails.

The consistency check is successful only if one of the following conditions holds, and it fails otherwise:

* If both ITEM_A and ITEM_B specify an authentication credential by value, then both ITEM_A and ITEM_B specify the same value.

* If one among ITEM_A and ITEM_B specifies an authentication credential by value VALUE while the other one specifies an authentication credential by reference REF, then REF is a valid reference for VALUE.

* If ITEM_A specifies an authentication credential by reference REF_A and ITEM_B specifies an authentication credential by reference REF_B, then REF_A or REF_B allows to retrieving the value VALUE of an authentication credential from a local or remote storage, such that both REF_A and REF_B are a valid reference for VALUE.

The peer P1 performs the consistency check above as soon as it has both ITEM_A and ITEM_B available. If P1 acts as the Responder, that is the case when processing the incoming LAKE message_3. If P1 acts as the Initiator, that is the case when processing the incoming LAKE message_2 or message_4, i.e., whichever of the two messages includes ITEM_B in an EAD item of its EAD field.

# Using LAKE over CoAP with Block-Wise # {#sec-block-wise}

{{Section A.2 of RFC9528}} specifies how to transfer LAKE over CoAP {{RFC7252}}. In such a case, LAKE messages (potentially prepended by a LAKE connection identifier) are transported in the payload of CoAP requests and responses, according to the LAKE forward message flow or the LAKE reverse message flow. Furthermore, {{Section A.1 of RFC9528}} specifies how to derive an OSCORE Security Context {{RFC8613}} from a LAKE session.

Building on that, {{RFC9668}} further details the use of LAKE with CoAP and OSCORE. In particular, it specifies an optimization approach for the LAKE forward message flow that combines the LAKE execution with the first subsequent OSCORE transaction. This is achieved by means of a "LAKE + OSCORE request" (denoted as "EDHOC + OSCORE request" in {{RFC9668}}), i.e., a single CoAP request message that conveys both LAKE message_3 of the ongoing LAKE session and the OSCORE-protected application data, where the latter is protected with the OSCORE Security Context derived from that LAKE session.

This section provides guidelines and recommendations for CoAP endpoints supporting Block-wise transfers for CoAP {{RFC7959}} and specifically for CoAP clients supporting the LAKE + OSCORE request defined in {{RFC9668}}. The use of Block-wise transfers can be desirable, e.g., for LAKE messages that include a large ID_CRED_I or ID_CRED_R, or that include a large EAD field.

The following especially considers a CoAP endpoint that may perform only "inner" Block-wise, but not "outer" Block-wise operations (see {{Section 4.1.3.4 of RFC8613}}). That is, the considered CoAP endpoint does not (further) split an OSCORE-protected message like an intermediary (e.g., a proxy) might do. This is the typical case for CoAP endpoints using OSCORE (see {{Section 4.1.3.4 of RFC8613}}).

## Notation

The rest of this section refers to the following notation:

* SIZE_BODY: the size in bytes of the data to be transmitted with CoAP. When Block-wise is used, such data is referred to as the "body" to be fragmented into blocks, each of which to be transmitted in one CoAP message.

  With the exception pertaining to LAKE message_3 described in the following paragraph, the considered body can in general be a LAKE message, potentially prepended by a LAKE connection identifier encoded as per {{Section 3.3 of RFC9528}}.

  When specifically using the LAKE + OSCORE request, the considered body is the application data to be protected with OSCORE, (whose first block is) to be sent together with LAKE message_3 as part of the LAKE + OSCORE request.

* SIZE_LAKE_M3: the size in bytes of LAKE message_3, if this is sent as part of the LAKE + OSCORE request. Otherwise, the size in bytes of LAKE message_3, plus, if included, the size in bytes of a prepended LAKE connection identifier encoded as per {{Section 3.3 of RFC9528}}.

* SIZE_MTU: the maximum amount of transmittable bytes before having to use Block-wise. This is, for example, 64 KiB as maximum datagram size when using UDP, or 1280 bytes as the maximum size for an IPv6 MTU.

* SIZE_OH: the size in bytes of the overall overhead due to all the communication layers underlying the application. This takes into account also the overhead introduced by the OSCORE processing.

* LIMIT = (SIZE_MTU - SIZE_OH): the practical maximum size in bytes to be considered by the application before using Block-wise.

* SIZE_BLOCK: the size in bytes of inner blocks.

* ceil(): the ceiling function.

## Pre-requirements for the LAKE + OSCORE Request # {#sec-block-wise-pre-req}

Before sending a LAKE + OSCORE request, a CoAP client has to perform the following checks. Note that, while the CoAP client is able to fragment the plain application data before any OSCORE processing, it cannot fragment the LAKE + OSCORE request or the LAKE message_3 added therein.

* If inner Block-wise is not used, hence SIZE_BODY <= LIMIT, the CoAP client must verify whether all the following conditions hold:

  - COND1: SIZE_LAKE_M3 <= LIMIT

  - COND2: (SIZE_BODY + SIZE_LAKE_M3) <= LIMIT

* If inner Block-wise is used, the CoAP client must verify whether all the following conditions hold:

  - COND3: SIZE_LAKE_M3 <= LIMIT

  - COND4: (SIZE_BLOCK + SIZE_LAKE_M3) <= LIMIT

In either case, if not all the corresponding conditions hold, the CoAP client should not send the LAKE + OSCORE request. Instead, the CoAP client can continue by switching to the purely sequential, original LAKE workflow (see {{Section A.2.1 of RFC9528}}). That is, the CoAP client first sends LAKE message_3 prepended by the LAKE Connection Identifier C_R encoded as per {{Section 3.3 of RFC9528}} and then sends the OSCORE-protected CoAP request once the LAKE execution is completed.

## Effectively Using Block-Wise

In order to avoid further fragmentation at lower layers when sending a LAKE + OSCORE request, the CoAP client has to use inner Block-wise if _any_ of the following conditions holds:

* COND5: SIZE_BODY > LIMIT

* COND6: (SIZE_BODY + SIZE_LAKE_M3) > LIMIT

In particular, consistent with {{sec-block-wise-pre-req}}, the SIZE_BLOCK used has to be such that the following condition also holds:

* COND7: (SIZE_BLOCK + SIZE_LAKE_M3) <= LIMIT

Note that the CoAP client might still use Block-wise due to reasons different from exceeding the size indicated by LIMIT.

The following shows the number of round trips for completing both the LAKE execution and the first OSCORE-protected exchange, under the assumption that the exchange of LAKE message_1 and LAKE message_2 does not result in using Block-wise.

If _both_ the conditions COND5 and COND6 hold, the use of Block-wise results in the following number of round trips experienced by the CoAP client.

* If the original LAKE execution workflow is used (see {{Section A.2.1 of RFC9528}}), the number of round trips RT_ORIG is equal to 1 + ceil(SIZE_LAKE_M3 / SIZE_BLOCK) + ceil(SIZE_BODY / SIZE_BLOCK).

* If the optimized LAKE execution workflow is used (see {{Section 3 of RFC9668}}), the number of round trips RT_COMB is equal to 1 + ceil(SIZE_BODY / SIZE_BLOCK).

It follows that RT_COMB < RT_ORIG, i.e., the optimized LAKE execution workflow always yields a lower number of round trips.

Instead, the convenience of using the optimized LAKE execution workflow becomes questionable if _both_ the following conditions hold:

* COND8: SIZE_BODY <= LIMIT

* COND9: (SIZE_BODY + SIZE_LAKE_M3) > LIMIT

That is, since SIZE_BODY <= LIMIT, using Block-wise would not be required when using the original LAKE execution workflow, provided that SIZE_LAKE_M3 <= LIMIT still holds.

At the same time, using the combined workflow is in itself what actually triggers the use of Block-wise, since (SIZE_BODY + SIZE_LAKE_M3) > LIMIT.

Therefore, the following round trips are experienced by the CoAP client.

*  The original LAKE execution workflow run without using Block-wise results in a number of round trips RT_ORIG equal to 3.

*  The optimized LAKE execution workflow run using Block-wise results in a number of round trips RT_COMB equal to 1 + ceil(SIZE_BODY / SIZE_BLOCK).

It follows that RT_COMB >= RT_ORIG, i.e., the optimized LAKE execution workflow might still be not worse than the original LAKE execution workflow in terms of round trips. This is the case only if the SIZE_BLOCK used is such that ceil(SIZE_BODY / SIZE_BLOCK) is equal to 2, i.e., the plain application data is fragmented into only 2 inner blocks, and thus the LAKE + OSCORE request is followed by only one more request message transporting the last block of the body.

However, even in such a case, there would be no advantage in terms of round trips compared to the original workflow, while still requiring the CoAP client and the CoAP server to perform the processing due to using the LAKE + OSCORE request and Block-wise transferring.

Therefore, if both the conditions COND8 and COND9 hold, the CoAP client should not send the LAKE + OSCORE request. Instead, the CoAP client should continue by switching to the original LAKE execution workflow. That is, the CoAP client first sends LAKE message_3 prepended by the LAKE Connection Identifier C_R encoded as per {{Section 3.3 of RFC9528}} and then sends the OSCORE-protected CoAP request once the LAKE execution is completed.

# Operational Considerations

There are no new operations or manageability requirements introduced by this document, which provides considerations for implementers of the LAKE protocol and does not update the protocol or introduce extensions thereof.

# Security Considerations # {#sec-security-considerations}

This document provides considerations for implementations of the LAKE protocol. The security considerations compiled in {{Section 9 of RFC9528}} and in {{Section 7 of RFC9668}} apply. The compliance requirements for implementations that are listed in {{Section 8 of RFC9528}} also apply.

It is foreseeable that the LAKE protocol will be extended (e.g., in terms of new cipher suites, new methods, and new types of authentication credentials) and that external security applications will be integrated into LAKE by embedding the transport of their data in LAKE EAD items. For implementations that support such extensions and external applications, the related security considerations and compliance requirements also apply.

## Assessing the Correctness of Implementations

Tools relying on fuzz testing such as EDHOC-Fuzzer {{EDHOC-Fuzzer}} can help assess the correctness of implementations of the LAKE protocol and of external security applications integrated into LAKE.

Such tools help finding and amending implementation errors especially related to the following points:

* Non-conformance with the protocol specification (e.g., unintended deviations in performing the protocol steps), which can be a potential source of security vulnerabilities in addition to performance deficiencies.

* Presence of inappropriate states and state transitions in the modeling of the LAKE execution, e.g., states that are impossible to reach and traverse or that are not part of the protocol specification (which is a particular case of non-conformance).

  These states and transitions should be amended or removed, in order to reduce the memory footprint and code complexity and to simplify the implementation, thus reducing the risks of bugs and related security vulnerabilities.

# IANA Considerations

This document has no actions for IANA.

--- back

# Example of Side-Processor Object # {#sec-example-spo}

This appendix builds on {{sec-message-side-processing}} and provides a detailed example of how the SPO can be implemented to perform the side processing of incoming LAKE messages.

## LAKE message_1 ## {#sec-message-side-processing-m1}

During the processing of an incoming LAKE message_1, LAKE invokes the SPO only once, after the Responder peer has successfully decoded the message and accepted the selected cipher suite.

If the EAD_1 field is present, the SPO processes the EAD items included therein.

Once all such EAD items have been processed, the SPO transfers control back to LAKE. When doing so, the SPO also provides LAKE with any produced EAD items to include in the EAD field of the next outgoing LAKE message.

Then, LAKE resumes its execution and advances its protocol state.

Future extensions of LAKE or external security applications integrated into LAKE might require a processing of LAKE message_1 that is more advanced than the currently expected one. In particular, an EAD item conveyed in LAKE message_1 might specify the authentication credential CRED associated with the Initiator (by value or by reference), as wrapped in a cryptographically protected "envelope". In such a case, the processing of an incoming LAKE message_1 shares similarities with that of an incoming LAKE message_2 or message_3 (see {{sec-message-side-processing-m2-m3}}), as it is further elaborated in {{sec-message-side-processing-m1-advanced}}.

## LAKE message_4 ## {#sec-message-side-processing-m4}

During the processing of an incoming LAKE message_4, LAKE invokes the SPO only once, after the Initiator peer has successfully decrypted the message.

If the EAD_4 field is present, the SPO processes the EAD items included therein.

Once all such EAD items have been processed, the SPO transfers control back to LAKE, which resumes its execution and advances its protocol state.

## LAKE message_2 and message_3 ## {#sec-message-side-processing-m2-m3}

The following refers to "message_X" as an incoming LAKE message_2 or message_3, and to "message verification" as the verification of Signature_or_MAC_X in message_X.

During the processing of a message_X, LAKE invokes the SPO two times:

* Right after message_X has been decrypted and before its verification starts. Following this invocation, the SPO performs the actions described in {{sec-pre-verif}}.

* Right after message_X has been successfully verified. Following this invocation, the SPO performs the actions described in {{sec-post-verif}}.

The flowchart in {{sec-m2-m3-flowchart}} shows the different steps taken for processing an incoming message_X.

### Pre-Verification Side Processing # {#sec-pre-verif}

The pre-verification side processing occurs in two sequential phases, namely PHASE_1 (see {{sec-pre-verif-phase-1}}) and PHASE_2 (see {{sec-pre-verif-phase-2}}).

#### PHASE\_1 # {#sec-pre-verif-phase-1}

During PHASE_1, the SPO at the recipient peer P determines CRED, i.e., the authentication credential associated with the other peer to be used in the ongoing LAKE session. In particular, the SPO first checks whether expected EAD items are absent in message_X (see {{sec-message-side-processing}}), and then performs the following steps.

1. The SPO determines CRED based on ID_CRED_X or on an EAD item included in message_X.

   Those may specify CRED by value or by reference, including a URI or other external reference where CRED can be retrieved from.

   If CRED is already stored, the SPO moves to Step 2. Otherwise, the SPO moves to Step 3.

2. The SPO determines if the stored CRED is currently trusted and valid, e.g., by verifying that CRED has not expired and has not been revoked.

   Performing such a validation might require the SPO to first process an EAD item included in message_X. For example, it can be an EAD item in LAKE message_2 that confirms or revokes the validity of CRED_R specified by ID_CRED_R, as the result of an OCSP process {{RFC6960}}.

   In the case that CRED is determined to be valid, the SPO moves to Step 9. Otherwise, the SPO moves to Step 11.

3. The SPO attempts to retrieve CRED via ID_CRED_X or an EAD item considered at Step 1. Then, the SPO moves to Step 4.

4. If the retrieval of CRED has succeeded, the SPO moves to Step 5. Otherwise, the SPO moves to Step 11.

5. If the enforced trust policy for new authentication credentials is "NO-LEARNING" and P does not admit any exceptions that are acceptable to enforce for message_X (see {{sec-policy-no-learning}}), the SPO moves to Step 11. Otherwise, the SPO moves to Step 6.

6. If this step has been reached, the peer P is not already storing the retrieved CRED and, at the same time, it enforces either the trust policy "LEARNING" or the trust policy "NO-LEARNING" while also enforcing an exception acceptable for message_X (see {{sec-policy-no-learning}}).

   Consistent with that, the SPO determines if CRED is currently valid, e.g., by verifying that CRED has not expired and has not been revoked.

   Validating CRED might require the SPO to first process an EAD item included in message_X. For example, it can be an OCSP response {{RFC6960}} for validating CRED_R as a public key certificate transported by value or reference in ID_CRED_R.

   After successfully validating CRED, the peer P can typically consider CRED as ultimately trusted as well. However, there can be cases where P requires to obtain additional information before doing so.

   If such additional information can be retrieved from message_X (e.g., from an EAD item included therein), then P uses it to assess if CRED is trusted. Otherwise, if such additional information is expected later on during the LAKE session, it can be acceptable for P to consider CRED as provisionally trusted.

   {{sec-trust-models-ela}} discusses the ELA procedure defined in {{I-D.ietf-lake-authz}}, as a case in point where additional information required by the peer P to trust CRED could not be included in the same message that specifies CRED.

   After completing the validation and trust assessment of CRED, the SPO moves to Step 7.

7. If CRED has been determined valid and (provisionally) trusted, the SPO moves to Step 8. Otherwise, the SPO moves to Step 11.

8. The SPO stores CRED as a valid and (provisionally) trusted authentication credential associated with the other peer, together with corresponding authentication credential identifiers (see {{sec-trust-models}}). Then, the SPO moves to Step 9.

9. The SPO checks if CRED is fine to use in the context of the ongoing LAKE session, also depending on the specific identity of the other peer (see {{Sections 3.5 and D.2 of RFC9528}}).

   If this is the case, the SPO moves to Step 10. Otherwise, the SPO moves to Step 11.

10. P uses CRED as authentication credential associated with the other peer in the ongoing LAKE session.

    Then, PHASE_1 ends and the pre-verification side processing moves to the next PHASE_2 (see {{sec-pre-verif-phase-2}}).

11. The SPO has not found a valid and (provisionally) trusted authentication credential associated with the other peer that can be used in the ongoing LAKE session. Therefore, the LAKE session with the other peer is aborted.

#### PHASE\_2 # {#sec-pre-verif-phase-2}

During PHASE_2, the SPO processes any EAD item included in message_X such that both the following conditions hold:

* The EAD item has _not_ already been processed during PHASE_1.

* The EAD item can be processed before performing the verification of message_X.

Once all such EAD items have been processed, the SPO transfers control back to LAKE, which either aborts the ongoing LAKE session or continues the processing of message_X with its corresponding message verification.

### Post-Verification Side Processing # {#sec-post-verif}

During the post-verification side processing, the SPO processes any EAD item included in message_X such that the processing of that EAD item had to wait for completing the successful message verification.

The late processing of such EAD items is typically due to the fact that a pre-requirement has to be fulfilled first.

For example, the recipient peer P has to have first verified that the other peer does possess the private key corresponding to the public key specified by CRED, i.e., the authentication credential associated with the other peer that was determined during the pre-verification side processing (see {{sec-pre-verif}}). This requirement is fulfilled after a successful verification of message_X.

Once all such EAD items have been processed, the SPO transfers control back to LAKE. When doing so, the SPO also provides LAKE with any produced EAD items to include in the EAD field of the next outgoing LAKE message.

Then, LAKE resumes its execution and advances its protocol state.

### Flowchart # {#sec-m2-m3-flowchart}

The flowchart in {{fig-flowchart-spo-low-level}} shows the different steps taken for processing an incoming LAKE message_2 and message_3.

~~~~~~~~~~~ aasvg
  Incoming
  LAKE message_X
  (X = 2 or 3)

          |
          |
          v
 +-------------------+  ---+
 | Decode message_X  |     |
 +-------------------+     |
          |                |
          |                |
          v                |
 +-------------------+     |
 | Retrieve the      |     +--- (Core LAKE Processing)
 | protocol state    |     |
 +-------------------+     |
          |                |
          |                |
          v                |
 +-------------------+     |
 | Decrypt message_X |     |
 +-------------------+  ---+
          |
          |

 Control transferred to
 the side-processor object

          |
+---------|-----------------------------------------------------------+
|         |             Pre-verification side processing (PHASE_1)    |
|         |                                                           |
| +------------------------+                                          |
| | Check whether expected |                                          |
| | EAD items are absent   |                                          |
| +------------------------+                                          |
|         |                                                           |
|         |                                                           |
|         v                                                           |
| +---------------------+     +--------------+     +-------------+    |
| | 1. Does ID_CRED_X   | NO  | 3. Retrieve  |     | 4. Is the   |    |
| | or an EAD item      |---->| CRED via     |---->| retrieval   |    |
| | point to an already |     | ID_CRED_X or |     | of CRED     |    |
| | stored CRED?        |     | an EAD item  |     | successful? |    |
| +---------------------+     +--------------+     +-------------+    |
|         |                                          |         |      |
|         |                                          | NO      | YES  |
|         |                         +----------------+         |      |
|         |                         |                          |      |
|         | YES                     |                          |      |
|         v                         v                          v      |
| +-----------------+ NO      +-----------+   YES +-----------------+ |
| | 2. Is this CRED |-------->| 11. Abort |<------| 5. Is the trust | |
| | still valid and |         | the LAKE  |       | policy used     | |
| | trusted?        |         | session   |       | "NO-LEARNING",  | |
| +-----------------+         |           |       | without any     | |
|         |                   |           |       | acceptable      | |
|         |                   |           |       | exceptions?     | |
|         |                   |           |       +-----------------+ |
|         | YES               |           |                    |      |
|         v                   |           |     Here the trust | NO   |
| +--------------------+ NO   |           |     policy used is |      |
| | 9. Is this CRED    |----->|           |     "LEARNING", or |      |
| | good to use in the |      +-----------+     "NO-LEARNING"  |      |
| | context of this    |               ^        together with  |      |
| | LAKE session?      |<-----+        |        an overriding  |      |
| +--------------------+      |        |        exception      |      |
|         |                   |        |                       |      |
|         |                   |        |                       v      |
|         |                   |        |           +---------------+  |
|         |                   |        |           | 6. Assess if  |  |
|         |                   |        |           | CRED is valid |  |
|         |                   |        |           | and trusted   |  |
|         |                   |        |           +---------------+  |
|         |                   |        |                       |      |
|         | YES               |        | NO                    |      |
|         |                   |        |                       v      |
|         |                   |     +-------------------------------+ |
|         |                   |     | 7. Is CRED valid and          | |
|         |                   |     | (provisionally) trusted?      | |
|         |                   |     +-------------------------------+ |
|         |                   |        |                              |
|         |                   |        | YES                          |
|         v                   |        v                              |
| +------------------+        |     +-------------------------------+ |
| | 10. Continue by  |        |     | 8. Store CRED as valid and    | |
| | considering this |        +-----| (provisionally) trusted.      | |
| | CRED as the      |              |                               | |
| | authentication   |              | Pair CRED with consistent     | |
| | credential       |              | credential identifiers, for   | |
| | associated with  |              | each supported type of        | |
| | the other peer   |              | credential identifier.        | |
| +------------------+              +-------------------------------+ |
|         |                                                           |
+---------|-----------------------------------------------------------+
          |
          |
+---------|-----------------------------------------------------------+
|         |            Pre-verification side processing (PHASE_2)     |
|         v                                                           |
| +--------------------------------------------------------+          |
| | Process the EAD items that have not been processed yet |          |
| | and that can be processed before message verification  |          |
| +--------------------------------------------------------+          |
|         |                                                           |
+---------|-----------------------------------------------------------+
          |
          |
          v

 Control transferred back
 to the core LAKE processing

          |
          |
          v
 +------------------+
 | Verify message_X | (Core LAKE processing)
 +------------------+
          |
          |
          v

 Control transferred to
 the side-processor object

          |
+---------|----------------------------------------+
|         |           Post-verification processing |
|         v                                        |
| +---------------------------------------------+  |
| | Process the EAD items that have to be       |  |
| | processed (also) after message verification |  |
| +---------------------------------------------+  |
|         |                                        |
|         |                                        |
|         v                                        |
| +--------------------------------------------+   |
| | Make all the results of the EAD processing |   |
| | available to build the next LAKE message   |   |
| +--------------------------------------------+   |
|         |                                        |
+---------|----------------------------------------+
          |
          |
          v

 Control transferred back
 to the core LAKE processing

          |
          |
          v
 +----------------+
 | Advance the    | (Core LAKE processing)
 | protocol state |
 +----------------+
~~~~~~~~~~~
{: #fig-flowchart-spo-low-level title="Processing Steps for Incoming LAKE message_2 and message_3." artwork-align="center"}

## Foreseen Advanced Processing of Incoming LAKE message\_1 # {#sec-message-side-processing-m1-advanced}

As mentioned in {{sec-message-side-processing-m1}}, future developments in LAKE and in related external security applications might rely on an EAD item in LAKE message_1 that specifies the authentication credential CRED associated with the Initiator (by value or by reference), as wrapped in a cryptographically protected "envelope".

In order to handle such a case, the processing of an incoming LAKE message_1 as described in {{sec-message-side-processing-m1}} is extended with additional steps performed by the SPO.

Such an extended side processing shares similarities with that of an incoming LAKE message_2 or message_3 (see {{sec-message-side-processing-m2-m3}}). In particular, similarly to what is compiled in {{sec-pre-verif-phase-1}} and {{sec-pre-verif-phase-2}}, the SPO first checks whether expected EAD items are absent in message_X (see {{sec-message-side-processing}}) and then performs the following steps.

* (0) The SPO checks the presence of an EAD item that specifies the authentication credential CRED associated with the Initiator (by value or by reference).

  If no such EAD item is found, the SPO moves to Step 12. Otherwise, the SPO moves to Step 1.

* (1) The SPO determines CRED based on an EAD item retrieved at Step 0.

  The EAD item can specify CRED by value or by reference, including a URI or other external reference where CRED can be retrieved from.

  If CRED is already stored, the SPO moves to Step 2. Otherwise, the SPO moves to Step 3.

* (2) The SPO determines if the stored CRED is currently trusted and valid, e.g., by verifying that CRED has not expired and has not been revoked.

  Performing such a validation might require the SPO to first process an EAD item included in message_1.

  In the case that CRED is determined to be valid, the SPO moves to Step 9. Otherwise, the SPO moves to Step 11.

* (3) The SPO attempts to retrieve CRED via an EAD item considered at Step 1. Then, the SPO moves to Step 4.

* (4) If the retrieval of CRED has succeeded, the SPO moves to Step 5. Otherwise, the SPO moves to Step 11.

* (5) If the enforced trust policy for new authentication credentials is "NO-LEARNING" and P does not admit any exceptions that are acceptable to enforce for message_1 (see {{sec-policy-no-learning}}), the SPO moves to Step 11. Otherwise, the SPO moves to Step 6.

* (6) If this step has been reached, the peer P is not already storing the retrieved CRED and, at the same time, it enforces either the trust policy "LEARNING" or the trust policy "NO-LEARNING" while also enforcing an exception acceptable for message_1 (see {{sec-policy-no-learning}}).

  Consistent with that, the SPO determines if CRED is currently valid, e.g., by verifying that CRED has not expired and has not been revoked.

  Validating CRED might require the SPO to first process an EAD item included in message_1.

  After successfully validating CRED, the peer P can typically consider CRED as ultimately trusted as well. However, there can be cases where P requires to obtain additional information before doing so.

  If such additional information can be retrieved from message_1 (e.g., from an EAD item included therein), then P uses it to assess if CRED is trusted. Otherwise, if such additional information is expected later on during the LAKE session, it can be acceptable for P to consider CRED as provisionally trusted.

  After completing the validation and trust assessment of CRED, the SPO moves to Step 7.

* (7) If CRED has been determined valid and (provisionally) trusted, the SPO moves to Step 8. Otherwise, the SPO moves to Step 11.

* (8) The SPO stores CRED as a valid and (provisionally) trusted authentication credential associated with the other peer, together with corresponding authentication credential identifiers (see {{sec-trust-models}}). Then, the SPO moves to Step 9.

* (9) The SPO checks if CRED is fine to use in the context of the ongoing LAKE session, also depending on the specific identity of the other peer (see {{Sections 3.5 and D.2 of RFC9528}}).

  If this is the case, the SPO moves to Step 10. Otherwise, the SPO moves to Step 11.

* (10) P uses CRED as authentication credential associated with the other peer in the ongoing LAKE session. Then, the SPO moves to Step 12.

* (11) The SPO has not found a valid and (provisionally) trusted authentication credential associated with the other peer that can be used in the ongoing LAKE session. Therefore, the LAKE session with the other peer is aborted.

* (12) The SPO processes any EAD item included in message_1 that has not already been processed.

  Once all such EAD items have been processed, the SPO transfers control back to LAKE. When doing so, the SPO also provides LAKE with any produced EAD items to include in the EAD field of the next outgoing LAKE message.

The flowchart in {{fig-flowchart-spo-low-level-m1-advanced}} shows the different steps taken for the advanced processing of an incoming LAKE message_1 defined above.

~~~~~~~~~~~ aasvg
  Incoming
  LAKE message_1

           |
           |
           v
 +-------------------+  ---+
 | Decode message_1  |     |
 +-------------------+     |
           |               |
           |               +--- (Core LAKE Processing)
           v               |
 +-------------------+     |
 | Accepted selected |     |
 | cipher suite      |     |
 +-------------------+  ---+
           |
           |

 Control transferred to
 the side-processor object

           |
+----------|----------------------------------------------------------+
|          |                                      Side processing     |
|          |                                                          |
| +------------------------+                                          |
| | Check whether expected |                                          |
| | EAD items are absent   |                                          |
| +------------------------+                                          |
|          |                                                          |
|          |                                                          |
|          v                                                          |
| +--------------------+                                              |
| | 0. Does an EAD     |                                              |
| | item specify CRED? |                                              |
| +--------------------+                                              |
|  |       |                                                          |
|  | NO    | YES                                                      |
|  |       v                                                          |
|  |   +----------------+     +-------------+      +-------------+    |
|  |   | 1. Does an EAD | NO  | 3. Retrieve |      | 4. Is the   |    |
|  |   | item point to  |---->| CRED via    |----->| retrieval   |    |
|  |   | an already     |     | an EAD item |      | of CRED     |    |
|  |   | stored CRED?   |     +-------------+      | successful? |    |
|  |   +----------------+                          +-------------+    |
|  |       |                                         |         |      |
|  |       |                                         | NO      | YES  |
|  |       |                        +----------------+         |      |
|  |       |                        |                          |      |
|  |       | YES                    |                          |      |
|  |       v                        v                          v      |
|  |  +-----------------+ NO  +-----------+   YES +-----------------+ |
|  |  | 2. Is this CRED |---->| 11. Abort |<------| 5. Is the trust | |
|  |  | still valid and |     | the LAKE  |       | policy used     | |
|  |  | trusted?        |     | session   |       | "NO-LEARNING",  | |
|  |  +-----------------+     |           |       | without any     | |
|  |       |                  |           |       | acceptable      | |
|  |       |                  |           |       | exceptions?     | |
|  |       |                  |           |       +-----------------+ |
|  |       | YES              |           |                    |      |
|  |       v                  |           |     Here the trust | NO   |
|  |  +-----------------+ NO  |           |     policy used is |      |
|  |  | 9. Is this CRED |---->|           |     "LEARNING", or |      |
|  |  | good to use in  |     +-----------+     "NO-LEARNING"  |      |
|  |  | the context of  |              ^        together with  |      |
|  |  | this LAKE       |<----+        |        an overriding  |      |
|  |  | session?        |     |        |        exception      |      |
|  |  +-----------------+     |        |                       |      |
|  |      |                   |        |                       v      |
|  |      |                   |        |            +---------------+ |
|  |      |                   |        |            | 6. Assess if  | |
|  |      |                   |        |            | CRED is valid | |
|  |      |                   |        |            | and trusted   | |
|  |      |                   |        |            +---------------+ |
|  |      |                   |        |                       |      |
|  |      | YES               |        | NO                    |      |
|  |      |                   |        |                       v      |
|  |      |                   |     +-------------------------------+ |
|  |      |                   |     | 7. Is CRED valid and          | |
|  |      |                   |     | (provisionally) trusted?      | |
|  |      |                   |     +-------------------------------+ |
|  |      |                   |        |                              |
|  |      |                   |        | YES                          |
|  |      v                   |        v                              |
|  |  +------------------+    |     +-------------------------------+ |
|  |  | 10. Continue by  |    |     | 8. Store CRED as valid and    | |
|  |  | considering this |    +-----| (provisionally) trusted.      | |
|  |  | CRED as the      |          |                               | |
|  |  | authentication   |          | Pair CRED with consistent     | |
|  |  | credential       |          | credential identifiers, for   | |
|  |  | associated with  |          | each supported type of        | |
|  |  | the other peer   |          | credential identifier.        | |
|  |  +------------------+          +-------------------------------+ |
|  |      |                                                           |
|  |      |                                                           |
|  v      v                                                           |
| +-------------------------------------------------------------+     |
| | 12. Process the EAD items that have not been processed yet. |     |
| |                                                             |     |
| | Make all the results of the EAD processing available to     |     |
| | build the next LAKE message.                                |     |
| +-------------------------------------------------------------+     |
|         |                                                           |
+---------|-----------------------------------------------------------+
          |
          |
          v

 Control transferred back
 to the core LAKE processing

          |
          |
          v
 +----------------+
 | Advance the    | (Core LAKE processing)
 | protocol state |
 +----------------+
~~~~~~~~~~~
{: #fig-flowchart-spo-low-level-m1-advanced title="Processing Steps for Incoming LAKE message_1." artwork-align="center"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -07 to -08 ## {#sec-07-08}

* Renamed EDHOC to LAKE as appropriate.

* Updated text and figures on what happens if rerunning LAKE fails.

* Revised handling of invalid application keys or bound access rights become invalid.

* Retaining the latest state of completed sessions does not need persistent storage.

* Generalized handling of incoming error messages.

* Exception on unauthenticated operation moved to separate subsection.

* Editorial split between what the SPO provides and an example of how it can be implemented.

## Version -06 to -07 ## {#sec-06-07}

* Discussed retention of completed EDHOC sessions.

* Discussed handling of incoming EDHOC error messages in a completed EDHOC session.

* Clarifications:

  * An EAD field can include one or more EAD items.

  * Use of a new EAD item in the EDHOC and OSCORE profile of ACE.

  * Table summarizing expected behavior for different trust policies.

  * Scope limited to authentication methods defined in RFC 9528.

* Consistency alignments with draft-ietf-ace-edhoc-oscore-profile.

* Editorial fixes and improvements.

## Version -05 to -06 ## {#sec-05-06}

* Generalized trust assessment of authentication credentials.

* Revised discussion on the ELA procedure, based on upcoming updates expected in version -07 of draft-ietf-lake-authz.

* Added side-processing check about the absence of expected EAD items in incoming EDHOC messages.

* Added "Operational Considerations" section.

* Editorial fixes and improvements.

## Version -04 to -05 ## {#sec-04-05}

* Minor clarifications.

* Editorial fixes and improvements.

## Version -03 to -04 ## {#sec-03-04}

* Clarified and re-positioned exceptions to NO-LEARNING policy.

* Added security considerations.

* Appendix on foreseen advanced processing of incoming EDHOC message_1.

* Clarifications and editorial improvements.

## Version -02 to -03 ## {#sec-02-03}

* Consistent use of "trust policy" instead of "trust model".

* More modular presentation of trust policies and their enforcement.

* Alignment with use of EDHOC in the EDHOC and OSCORE profile of ACE.

* Note on follow-up actions for the application after EDHOC completion.

* Removed moot section on special handling when using the EDHOC and OSCORE profile of ACE.

* Consistency checks of authentication credentials from ID_CRED and EAD items.

* Updated reference.

* Clarifications and editorial improvements.

## Version -01 to -02 ## {#sec-01-02}

* Improved content on the EDHOC and OSCORE profile of ACE.

* Admit situation-specific exceptions to the "NO-LEARNING" policy.

* Using the EDHOC and OSCORE profile of ACE with the "NO-LEARNING" policy.

* Revised guidelines on using EDHOC with CoAP and Block-wise.

* Editorial improvements.

## Version -00 to -01 ## {#sec-00-01}

* Added considerations on trust policies when using the EDHOC and OSCORE profile of the ACE framework.

* Placeholder section on special processing when using the EDHOC and OSCORE profile of the ACE framework.

* Added considerations on using EDHOC with CoAP and Block-wise.

* Editorial improvements.

# Acknowledgments # {#acknowledgments}
{: numbered="no"}

The author sincerely thanks {{{Christian Amsüss}}}, {{{Geovane Fedrecheski}}}, {{{Rikard Höglund}}}, {{{Elsa Lopez-Perez}}}, {{{John Preuß Mattsson}}}, {{{Göran Selander}}}, {{{Brian Sipos}}}, {{{Yuxuan Song}}}, and {{{Mališa Vučinić}}} for their comments and feedback.

The work on this document has been partly supported by the Sweden's Innovation Agency VINNOVA and the Celtic-Next project CYPRESS.
