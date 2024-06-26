---
v: 3

title: Implementation Considerations for Ephemeral Diffie-Hellman Over COSE (EDHOC)
abbrev: Implementation Considerations for EDHOC
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
  RFC8613:
  RFC9528:

informative:
  RFC2986:
  RFC5280:
  RFC6960:
  RFC8392:
  RFC9200:
  I-D.ietf-ace-edhoc-oscore-profile:
  I-D.ietf-core-oscore-key-update:
  I-D.ietf-core-oscore-key-limits:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-lake-authz:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document provides considerations for guiding the implementation of the authenticated key exchange protocol Ephemeral Diffie-Hellman Over COSE (EDHOC).

--- middle

# Introduction # {#intro}

Ephemeral Diffie-Hellman Over COSE (EDHOC) {{RFC9528}} is a lightweight authenticated key exchange protocol, especially intended for use in constrained scenarios.

During the development of EDHOC, a number of side topics were raised and discussed, as emerging from reviews of the protocol latest design and from implementation activities. These topics were identified as strongly pertaining to the implementation of EDHOC rather than to the protocol in itself. Hence, they are not discussed in {{RFC9528}}, which rightly focuses on specifying the actual protocol.

At the same time, implementors of an application using the EDHOC protocol or of an "EDHOC library" enabling its use cannot simply ignore such topics, and will have to take them into account throughout their implementation work.

In order to prevent multiple, independent re-discoveries and assessments of those topics, as well as to facilitate and guide implementation activities, this document collects such topics and discusses them through considerations about the implementation of EDHOC. At a high-level, the topics in question are summarized below.

* Handling of completed EDHOC sessions when they become invalid, and of application keys derived from an EDHOC session when those become invalid. This topic is discussed in {{sec-session-handling}}.

* Enforcing of different trust models, with respect to learning new authentication credentials during an execution of EDHOC. This topic is discussed in {{sec-trust-models}}.

* Branched-off, side processing of incoming EDHOC messages, with particular reference to: i) fetching and validation of authentication credentials; and ii) processing of External Authorization Data (EAD) items, which in turn might play a role in the fetching and validation of authentication credentials. This topic is discussed in {{sec-message-side-processing}}.

## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

The reader is expected to be familiar with terms and concepts related to the EDHOC protocol and defined in {{RFC9528}}.

# Handling of Invalid EDHOC Sessions and Application Keys # {#sec-session-handling}

This section considers the most common situation where, given a certain peer, only the application at that peer has visibility and control of both:

* The EDHOC sessions at that peer; and

* The application keys for that application at that peer, including the knowledge of whether they have been derived from an EDHOC session, i.e., by means of the EDHOC_Exporter interface after the successful completion of an execution of EDHOC (see {{Section 4.2 of RFC9528}}).

Building on the above, the following expands on three relevant cases concerning the handling of EDHOC sessions and application keys, in the event that any of those becomes invalid.

As a case in point to provide more concrete guidance, the following also considers the specific case where "applications keys" stands for the keying material and parameters that compose an OSCORE Security Context {{RFC8613}} and that are derived from an EDHOC session (see {{Section A.1 of RFC9528}}).

Nevertheless, the same considerations are applicable in case EDHOC is used to derive other application keys, e.g., to key different security protocols than OSCORE or to provide the application with secure values bound to an EDHOC session.

## EDHOC Sessions Become Invalid ## {#sec-session-invalid}

The application at a peer P may have learned that a completed EDHOC session S has to be invalidated. When S is marked as invalid, the application at P purges S and deletes each set of application keys (e.g., the OSCORE Security Context) that was generated from S.

Then, the applications runs a new execution of the EDHOC protocol with the other peer. Upon successfully completing the EDHOC execution, the two peers derive and install a new set of application keys from this latest EDHOC session.

The flowchart in {{fig-flowchart-session-invalid}} shows the handling of an EDHOC session that has become invalid.

~~~~~~~~~~~ aasvg
Invalid     Delete the EDHOC session      Rerun     Derive and
EDHOC   --> and the application keys  --> EDHOC --> install new
session     derived from it                         application keys
~~~~~~~~~~~
{: #fig-flowchart-session-invalid title="Handling of an EDHOC Session that has Become Invalid" artwork-align="center"}

An EDHOC session may have become invalid, for example, because an authentication credential CRED_X may have expired, or because P may have learned from a trusted source that CRED_X has been revoked. This effectively invalidates CRED_X, and therefore also invalidates any EDHOC session where CRED_X was used as authentication credential of either peer in the session (i.e., P itself or the other peer). In such a case, the application at P has to additionally delete CRED_X and any stored, corresponding credential identifier.

## Application Keys Become Invalid ## {#sec-keys-invalid}

The application at a peer P may have learned that a set of application keys is not safe to use anymore. When such a set is specifically an OSCORE Security Context, the application may have learned that from the used OSCORE library or from an OSCORE layer that takes part to the communication stack.

A current set SET of application keys shared with another peer can become unsafe to use, for example, due to the following reasons.

* SET has reached its pre-determined expiration time; or

* SET has been established for a pre-defined, now elapsed amount of time, according to enforced application policies; or

* Some elements of SET have been used enough times to approach cryptographic limits that should not be passed, e.g., according to the properties of the specifically used security algorithms. With particular reference to an OSCORE Security Context, such limits are discussed in {{I-D.ietf-core-oscore-key-limits}}.

When this happens, the application at the peer P proceeds as follows.

1. If the following conditions both hold, then the application moves to step 2. Otherwise, it moves to step 3.

   * Let us define S as the EDHOC session from which the peer P has derived SET or the eldest SET's ancestor set of application keys. Then, since the completion of S with the other peer, the application at P has received from the other peer at least one message protected with any set of application keys derived from S. That is, P has persisted S (see {{Section 5.4.2 of RFC9528}}).

   * The peer P supports a key update protocol, as an alternative to performing a new execution of EDHOC with the other peer. When SET is specifically an OSCORE Security Context, this means that the peer P supports the key update protocol KUDOS defined in {{I-D.ietf-core-oscore-key-update}}.

2. The application at P runs the key update protocol mentioned at step 1 with the other peer, in order to update SET. When SET is specifically an OSCORE Security Context, this means that the application at P runs KUDOS with the other peer.

   If the key update protocol terminates successfully, the updated application keys are installed and no further actions are taken. Otherwise, the application at P moves to step 3.

3. The application at the peer P performs the following actions.

   * It deletes SET.

   * It deletes the EDHOC session from which SET was generated, or from which the eldest SET's ancestor set of application keys was generated before any key update occurred (e.g., by means of the EDHOC_KeyUpdate interface defined in {{Section H of RFC9528}} or other key update methods).

   * It runs a new execution of the EDHOC protocol with the other peer. Upon successfully completing the EDHOC execution, the two peers derive and install a new set of application keys from this latest EDHOC session.

The flowchart in {{fig-flowchart-keys-invalid}} shows the handling of a set of application keys that has become invalid.

~~~~~~~~~~~ aasvg
Invalid application keys

  |
  |
  v
                  NO
Are the          ----> Delete the application     ----> Rerun
application keys       keys and the EDHOC session       EDHOC
persisted?
                             ^        ^                   |
  |                          |        |                   |
  | YES                      |        |                   v
  v                          |        |
                             |        |           Derive and install
Is KUDOS    NO               |        |           new application keys
supported? ------------------+        |
                                      |
  |                                   |
  | YES                               |
  v                                   |
                                      |
Run KUDOS                             |
                                      |
  |                                   |
  |                                   |
  v                                   |
                                      |
Has KUDOS   NO                        |
succeeded? ---------------------------+

  |
  | YES
  v

Install the updated
application keys
~~~~~~~~~~~
{: #fig-flowchart-keys-invalid title="Handling of a set of Application Keys that has Become Invalid" artwork-align="center"}

## Application Keys or Bound Access Rights Become Invalid ## {#sec-keys-token-invalid}

The following considers two peers that use the ACE framework for authentication and authorization in constrained environments (ACE) {{RFC9200}}, and specifically the EDHOC and OSCORE profile of ACE defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

When doing so, one of the two peers acts as ACE Resource Server (RS) hosting protected resources. The other peer acts as ACE Client, requests from an ACE Authorization Server (AS) an Access Token that specifies access rights for accessing protected resources at the RS, and uploads the Access Token to the RS as part of the ACE workflow.

Consistent with the used EDHOC and OSCORE profile of ACE, the two peers run EDHOC in order to specifically derive an OSCORE Security Context as their shared set of application keys (see {{Section A.1 of RFC9528}}). In particular, the peer acting as ACE Client acts as EDHOC Initiator, while the peer acting as ACE RS acts as EDHOC Responder (see {{Section 2 of RFC9528}}). The successfully completed EDHOC session is bound to the Access Token.

After that, the peer acting as ACE Client can access the protected resources hosted at the other peer, according to the access rights specified in the Access Token. The communications between the two peers are protected by means of the established OSCORE Security Context, which is also bound to the used Access Token.

Later on, the application at one of the two peers P may have learned that the established OSCORE Security Context CTX is not safe to use anymore, e.g., from the used OSCORE library or from an OSCORE layer that takes part to the communication stack. The reasons that make CTX not safe to use anymore are the same ones discussed in {{sec-keys-invalid}} when considering a set of application keys in general, plus the event where the Access Token bound to CTX becomes invalid (e.g., it has expired or it has been revoked).

When this happens, the application at the peer P proceeds as follows.

1. If the following conditions both hold, then the application moves to step 2. Otherwise, it moves to step 3.

   * The Access Token is still valid. That is, it has not expired yet and the peer P is not aware that it has been revoked.

   * Let us define S as the EDHOC session from which the peer P has derived CTX or the eldest CTX's ancestor OSCORE Security Context. Then, since the completion of S with the other peer, the application at P has received from the other peer at least one message protected with any set of application keys derived from S. That is, P has persisted S (see {{Section 5.4.2 of RFC9528}}).

2. If the peer P supports the key update protocol KUDOS {{I-D.ietf-core-oscore-key-update}}, then P runs KUDOS with the other peer, in order to update CTX. If the execution of KUDOS terminates successfully, the updated OSCORE Security Context is installed and no further actions are taken.

   If the execution of KUDOS does not terminate successfully or if the peer P does not support KUDOS altogether, then the application at P moves to step 3.

3. The application at the peer P performs the following actions.

   * If the Access Token is not valid anymore, the peer P deletes all the EDHOC sessions associated with the Access Token, as well as the OSCORE Security Context derived from each of those sessions.

      If the peer P acted as ACE Client, then P obtains a new Access Token from the ACE AS, and uploads it to the other peer acting as ACE RS.

      Finally, the application at P moves to step 4.

   * If the Access Token is valid while the OSCORE Security Context CTX is not, then the peer P deletes CTX.

      After that, the peer P deletes the EDHOC session from which CTX was generated, or from which the eldest CTX's ancestor OSCORE Security Context was generated before any key update occurred (e.g., by means of KUDOS or other key update methods).

      Finally, the application at P moves to step 4.

4. The peer P runs a new execution of the EDHOC protocol with the other peer. Upon successfully completing the EDHOC execution, the two peers derive and install a new OSCORE Security Context from this latest EDHOC session.

The flowchart in {{fig-flowchart-keys-token-invalid}} shows the handling of an Access Token or of a set of application keys that have become invalid.

~~~~~~~~~~~ aasvg
Invalid token specifying CRED_I,
or invalid application keys

  |
  |
  v
              NO
Is the token ----> Delete the associated --> Obtain and --> Rerun ---+
still valid?       EDHOC sessions and        upload a       EDHOC    |
                   the application keys      new token               |
  |                derived from those                         ^      |
  |                                                           |      |
  | YES                                                       |      |
  v                                                           |      |
                                                              |      |
The application keys                                          |      |
are not valid anymore                                         |      |
                                                              |      |
  |                                                           |      |
  |                                                           |      |
  v                                                           |      |
                                                              |      |
Are the           NO                                          |      |
application keys -----> Delete the application keys and ------+      |
persisted?              the associated EDHOC session                 |
                                                                     |
  |                             ^        ^                           |
  | YES                         |        |                           |
  v                             |        |                           |
                                |        |                           |
Is KUDOS      NO                |        |                           |
supported? ---------------------+        |                           v
                                         |
  |                                      |           Derive and install
  | YES                                  |         new application keys
  v                                      |
                                         |
Run KUDOS                                |
                                         |
  |                                      |
  |                                      |
  v                                      |
                                         |
Has KUDOS     NO                         |
succeeded? ------------------------------+

  |
  | YES
  v

Install the updated
application keys
~~~~~~~~~~~
{: #fig-flowchart-keys-token-invalid title="Handling of an Access Token or of a set of Application Keys that have Become Invalid" artwork-align="center"}

# Trust Models for Learning New Authentication Credentials # {#sec-trust-models}

A peer P relies on authentication credentials of other peers, in order to authenticate those peers when running EDHOC with them.

There are different ways for P to acquire an authentication credential CRED of another peer. For example, CRED can be supplied to P out-of-band by a trusted provider.

Alternatively, CRED can be specified by the other peer during the EDHOC execution with P. This relies on EDHOC message_2 or message_3, whose respective ID_CRED_R and ID_CRED_I can specify CRED by value, or instead a URI or other external reference where CRED can be retrieved from (see {{Section 3.5.3 of RFC9528}}).

Also during the EDHOC execution, an External Authorization Data (EAD) field might include an EAD item that specifies CRED by value or reference. This is the case, e.g., for the EAD item defined in {{I-D.ietf-ace-edhoc-oscore-profile}}, which is used in the EAD_3 field of EDHOC message_3 and transports (a reference to) an Access Token that in turn specifies CRED_I by value or by reference.

When obtaining a new credential CRED, the peer P has to validate it before storing it. The validation steps to perform depend on the specific type of CRED (e.g., a public key certificate {{RFC5280}}{{I-D.ietf-cose-cbor-encoded-cert}}), and can rely on (the authentication credential of) a trusted third party acting as a trust anchor.

Upon retrieving a new CRED through the processing of a received EDHOC message and following the successful validation of CRED, the peer P stores CRED only if it assesses CRED to be also trusted, and must not store CRED otherwise.

An exception applies for the two unauthenticated operations described in {{Section D.5 of RFC9528}}, where a trust relationship with an unknown or not-yet-trusted endpoint is established later. That is, CRED is verified out-of-band at a later stage, or an EDHOC session key is bound to an identity out-of-band at a later stage.

If P stores CRED, then P will consider CRED as valid and trusted until it possibly becomes invalid, e.g., because it expires or because P gains knowledge that it has been revoked.

When storing CRED, the peer P should generate the authentication credential identifier(s) corresponding to CRED and store them as associated with CRED. For example, if CRED is a public key certificate, an identifier of CRED can be the hash of the certificate. In general, P should generate and associate with CRED one corresponding identifier for each type of authentication credential identifier that P supports and that is compatible with CRED.

In future executions of EDHOC with the other peer associated with CRED, this allows such other peer to specify CRED by reference, e.g., by indicating its credential identifier as ID_CRED_R/ID_CRED_I in the EDHOC message_2 or message_3 addressed to the peer P. In turn, this allows P to retrieve CRED from its local storage.

When processing a received EDHOC message M that specifies an authentication credential CRED, the peer P can enforce one of the following trust policies in order to determine whether to trust CRED.

* NO-LEARNING: according to this policy, the peer P trusts CRED if and only if P is already storing CRED at message reception time.

   That is, upon receiving M, the peer P can continue the execution of EDHOC only if both the following conditions hold.

   * P currently stores CRED, as specified by reference or by value in ID_CRED_I/ID_CRED_R or in the value of an EAD item; and

   * CRED is still valid, i.e., P believes CRED to not be expired or revoked.

* LEARNING: according to this policy, the peer P trusts CRED even if P is not already storing CRED at message reception time.

   That is, upon receiving M, the peer P performs the following steps.

   1. P retrieves CRED, as specified by reference or by value in ID_CRED_I/ID_CRED_R or in the value of an EAD item.

   2. P checks whether CRED is already being stored and if it is still valid. In such a case, P trusts CRED and can continue the EDHOC execution. Otherwise, P moves to step 3.

   3. P attempts to validate CRED. If the validation process is not successful, P aborts the EDHOC session with the other peer. Otherwise, P trusts and stores CRED, and can continue the EDHOC execution.

Irrespective of the adopted trust policy, P actually uses CRED only if it is determined to be fine to use in the context of the ongoing EDHOC session, also depending on the specific identity of the other peer (see {{Sections 3.5 and D.2 of RFC9528}}). If this is not the case, P aborts the EDHOC session with the other peer.

# Side Processing of Incoming EDHOC Messages # {#sec-message-side-processing}

This section describes an approach that EDHOC peers can use upon receiving EDHOC messages, in order to fetch/validate authentication credentials and to process External Authorization Data (EAD) items.

As per {{Section 9.1 of RFC9528}}, the EDHOC protocol provides a transport mechanism for conveying EAD items, but specifications defining those items have to set the ground for "agreeing on the surrounding context and the meaning of the information passed to and from the application".

The approach described in this section aims to help implementors navigate the surrounding context mentioned above, irrespective of the specific EAD items conveyed in the EDHOC messages. In particular, the described approach takes into account the following points.

* The fetching and validation of the other peer's authentication credential relies on ID_CRED_I in EDHOC message_2, or on ID_CRED_R in EDHOC message_3, or on the value of an EAD item. When this occurs upon receiving EDHOC message_2 or message_3, the decryption of the EDHOC message has to be completed first.

   The validation of the other peer's authentication credential might depend on using the value of an EAD item, which in turn has to be validated first. For instance, an EAD item within the EAD_2 field may contain a voucher to be used for validating the other peer's authentication credential (see {{I-D.ietf-lake-authz}}).

* Some EAD items may be processed only after having successfully verified the EDHOC message, i.e., after a successful verification of the Signature_or_MAC field.

   For instance, an EAD item within the EAD_3 field may contain a Certificate Signing Request (CSR) {{RFC2986}}. Hence, such an EAD item can be processed only once the recipient peer has attained proof of the other peer possessing its private key.

In order to conveniently handle such processing, the application can prepare in advance one "side-processor object" (SPO), which takes care of the operations above during the EDHOC execution.

In particular, the application provides EDHOC with the SPO before starting an EDHOC execution, during which EDHOC will temporarily transfer control to the SPO at the right point in time, in order to perform the required side-processing of an incoming EDHOC message.

Furthermore, the application has to instruct the SPO about how to prepare any EAD item such that: it has to be included in an outgoing EDHOC message; and it is independent of the processing of other EAD items included in incoming EDHOC messages. This includes, for instance, the preparation of padding EAD items.

At the right point in time during the processing of an incoming EDHOC message M at the peer P, EDHOC invokes the SPO and provides it with the following input:

* When M is EDHOC message_2 or message_3, an indication of whether this invocation is happening before or after the message verification (i.e., before or after having verified the Signature_or_MAC field).

* The full set of information related to the current EDHOC session. This especially includes the selected cipher suite and the ephemeral Diffie-Hellman public keys G_X and G_Y that the two peers have exchanged in the EDHOC session.

* The other peers' authentication credentials that the peer P stores.

* All the decrypted information elements retrieved from M.

* The EAD items included in M.

   - Note that EDHOC might do some preliminary work on M before invoking the SPO, in order to provide the SPO only with actually relevant EAD items. This requires the application to additionally provide EDHOC with the ead_labels of the EAD items that the peer P recognizes (see {{Section 3.8 of RFC9528}}).

      With such information available, EDHOC can early abort the current session in case M includes any EAD item which is both critical and not recognized by the peer P.

      If no such EAD items are found, EDHOC can remove any padding EAD item (see {{Section 3.8.1 of RFC9528}}), as well as any EAD item which is neither critical nor recognized (since the SPO is going to ignore it anyway). As a result, EDHOC is able to provide the SPO only with EAD items that will be recognized and that require actual processing.

   - Note that, after having processed the EAD items, the SPO might actually need to store them throughout the whole EDHOC execution, e.g., in order to refer to them also when processing later EDHOC messages in the current EDHOC session.

The SPO performs the following tasks on an incoming EDHOC message M.

* The SPO fetches and/or validates the other peer's authentication credential CRED, based on a dedicated EAD item of M or on the ID_CRED field of M (for EDHOC message_2 or message_3).

* The SPO processes the EAD items conveyed in the EAD field of M.

* The SPO stores the results of the performed operations, and makes such results available to the application.

* When the SPO has completed its side processing and transfers control back to EDHOC, the SPO provides EDHOC with the produced EAD items to include in the EAD field of the next outgoing EDHOC message. The production of such EAD items can be triggered, e.g., by:

   * The consumption of EAD items included in M; and

   * The execution of instructions that the SPO has received from the application, concerning EAD items to produce irrespective of other EAD items included in M.

The following subsections describe more in detail the actions performed by the SPO on the different, incoming EDHOC messages.

## EDHOC message_1

During the processing of an incoming EDHOC message_1, EDHOC invokes the SPO only once, after the Responder peer has successfully decoded the message and accepted the selected cipher suite.

If the EAD_1 field is present, the SPO processes the EAD items included therein.

Once all such EAD items have been processed the SPO transfers control back to EDHOC. When doing so, the SPO also provides EDHOC with any produced EAD items to include in the EAD field of the next outgoing EDHOC message.

Then, EDHOC resumes its execution and advances its protocol state.

## EDHOC message_4

During the processing of an incoming EDHOC message_4, EDHOC invokes the SPO only once, after the Initiator peer has successfully decrypted the message.

If the EAD_4 field is present, the SPO processes the EAD items included therein.

Once all such EAD items have been processed, the SPO transfers control back to EDHOC, which resumes its execution and advances its protocol state.

## EDHOC message_2 and message_3

The following refers to "message_X" as an incoming EDHOC message_2 or message_3, and to "message verification" as the verification of Signature_or_MAC_X in message_X.

During the processing of a message_X, EDHOC invokes the SPO two times:

* Right after message_X has been decrypted and before its verification starts. Following this invocation, the SPO performs the actions described in {{sec-pre-verif}}.

* Right after message_X has been successfully verified. Following this invocation, the SPO performs the actions described in {{sec-post-verif}}.

The flowcharts in {{sec-m2-m3-flowcharts}} show the high-level interaction between the core EDHOC processing and the SPO, as well as the different steps taken for processing an incoming message_X.

### Pre-Verification Side Processing # {#sec-pre-verif}

The pre-verification side processing occurs in two sequential phases, namely PHASE_1 and PHASE_2.

PHASE_1 - During PHASE_1, the SPO at the recipient peer P determines CRED, i.e., the other peer's authentication credential to use in the ongoing EDHOC session. In particular, the SPO performs the following steps.

1. The SPO determines CRED based on ID_CRED_X or on an EAD item in message_X.

   Those may specify CRED by value or by reference, including a URI or other external reference where CRED can be retrieved from.

   If CRED is already installed, the SPO moves to step 2. Otherwise, the SPO moves to step 3.

2. The SPO determines if the stored CRED is currently valid, e.g., by asserting that CRED has not expired and has not been revoked.

   Performing such a validation may require the SPO to first process an EAD item included in message_X. For example, it can be an EAD item in EDHOC message_2, which confirms or revokes the validity of CRED_R specified by ID_CRED_R, as the result of an OCSP process {{RFC6960}}.

   In case CRED is determined to be valid, the SPO moves to step 9. Otherwise, the SPO moves to step 11.

3. The SPO attempts to retrieve CRED, and then moves to step 4.

4. If the retrieval of CRED has succeeded, the SPO moves to step 5. Otherwise, the SPO moves to step 11.

5. If the enforced trust policy for new authentication credentials is "NO-LEARNING" (see {{sec-trust-models}}), the SPO moves to step 11. Otherwise, the SPO moves to step 6.

6. If this step has been reached, the peer P enforces the trust policy "LEARNING" (see {{sec-trust-models}}) and it is not already storing the retrieved CRED.

   Consistently, the SPO determines if CRED is currently valid, e.g., by asserting that CRED has not expired and has not been revoked. Then, the SPO moves to step 7.

   Validating CRED may require the SPO to first process an EAD item included in message_X. For example, it can be an EAD item in EDHOC message_2 that: i) specifies a voucher for validating CRED_R as a CWT Claims Set (CCS) {{RFC8392}} transported by value in ID_CRED_R (see {{I-D.ietf-lake-authz}}); or instead ii) an OCSP response {{RFC6960}} for validating CRED_R as a certificate transported by value or reference in ID_CRED_R.

7. If CRED has been determined valid, the SPO moves to step 8. Otherwise, the SPO moves to step 11.

8. The SPO stores CRED as a valid and trusted authentication credential associated with the other peer, together with corresponding authentication credential identifiers (see {{sec-trust-models}}). Then, the SPO moves to step 9.

9. The SPO checks if CRED is fine to use in the context of the ongoing EDHOC session, also depending on the specific identity of the other peer (see {{Sections 3.5 and D.2 of RFC9528}}).

   If this is the case, the SPO moves to step 10. Otherwise, the SPO moves to step 11.

10. P uses CRED as authentication credential of the other peer in the ongoing EDHOC session.

    Then, PHASE_1 ends, and the pre-verification side processing moves to the next PHASE_2 (see below).

11. The SPO has not found a valid authentication credential associated with the other peer that can be used in the ongoing EDHOC session. Therefore, the EDHOC session with the other peer is aborted.

PHASE_2 - During PHASE_2, the SPO processes any EAD item included in message_X such that both the following conditions hold.

* The EAD item has _not_ been already processed during PHASE_1.

* The EAD item can be processed before performing the verification of message_X.

Once all such EAD items have been processed, the SPO transfers control back to EDHOC, which either aborts the ongoing EDHOC session or continues the processing of message_X with its corresponding message verification.

### Post-Verification Side Processing # {#sec-post-verif}

During the post-verification side processing, the SPO processes any EAD item included in message_X such that the processing of that EAD item had to wait for completing the successful message verification.

The late processing of such EAD items is typically due to the fact that a pre-requirement has to be fulfilled first. For example, the recipient peer P has to have first asserted that the other peer does possess the private key corresponding to the public key of the other peer's authentication credential CRED determined during the pre-verification side processing (see {{sec-pre-verif}}). This requirement is fulfilled after a successful message verification of message_X.

Once all such EAD items have been processed, the SPO transfers control back to EDHOC. When doing so, the SPO also provides EDHOC with any produced EAD items to include in the EAD field of the next outgoing EDHOC message.

Then, EDHOC resumes its execution and advances its protocol state.

### Flowcharts # {#sec-m2-m3-flowcharts}

The flowchart in {{fig-flowchart-spo-high-level}} shows the high-level interaction between the core EDHOC processing and the SPO, with particular reference to an incoming EDHOC message_2 or message_3.

~~~~~~~~~~~ aasvg
EDHOC message_X
(X = 2 or 3)

      |
      |
+-----|---------------------------------------------------------------+
|     |                                         Core EDHOC processing |
|     v                                                               |
| +-----------+    +----------------+            +----------------+   |
| | Decode    |--->| Retrieve the   |            | Advance the    |   |
| | message_X |    | protocol state |            | protocol state |   |
| +-----------+    +----------------+            +----------------+   |
|                    |                             ^                  |
|                    |                             |                  |
|                    v                             |                  |
|      +--------------+    +--------------------+  |                  |
|      | Decrypt      |    | Verify             |  |                  |
|      | CYPHERTEXT_X |    | Signature_or_MAC_X |  |                  |
|      +--------------+    +--------------------+  |                  |
|                |           ^           |         |                  |
|                |           |           |         |                  |
+----------------|-----------|-----------|---------|------------------+
                 |           |           |         |
                 |           |           |         | .................
          Divert |      Get  |    Divert |    Get  | : EAD items     :
                 |      back |           |    back | : for the next  :
                 |           |           |         | : EDHOC message :
                 |           |           |         | :...............:
                 |           |           |         |
+----------------|-----------|-----------|---------|------------------+
|                |           |           |         |                  |
|                v           |           v         |                  |
| +---------------------------+     +-----------------------------+   |
| | a) Retrieval and          |     | Processing of               |   |
| |    validation of CRED_X;  |     | post-verification EAD items |   |
| | b) Trust assessment       |     +-----------------------o-----+   |
| |    of CRED_X;             |                             |         |
| | c) Processing of          o-------- Shared state -------o         |
| |    pre-verification       |                                       |
| |    EAD items              |        ......................         |
| |                           |        : Instructions about :         |
| | - (a) and (c) might have  |        : EAD items to       :         |
| |   to occur in parallel    |        : unconditionally    :         |
| | - (b) depends on the      |        : produce for the    :         |
| |   used trust model        |        : next EDHOC message :         |
| +---------------------------+        :....................:         |
|                                                                     |
|                                               Side-Processor Object |
+---------------------------------------------------------------------+
~~~~~~~~~~~
{: #fig-flowchart-spo-high-level title="High-Level Interaction Between the Core EDHOC Processing and the Side-Processor Object (SPO)" artwork-align="center"}

The flowchart in {{fig-flowchart-spo-low-level}} shows the different steps taken for processing an incoming EDHOC message_2 and message_3.

~~~~~~~~~~~ aasvg
  Incoming
  EDHOC message_X
  (X = 2 or 3)

          |
          |
          v
 +-------------------+
 | Decrypt message_X |  (Core EDHOC Processing)
 +-------------------+
          |
          |

 Control transferred to
 the side-processor object

          |
+---------|---------------------------------------------------------+
|         |           Pre-verification side processing (PHASE_1)    |
|         v                                                         |
| +---------------------+     +--------------+    +-------------+   |
| | 1. Does ID_CRED_X   | NO  | 3. Retrieve  |    | 4. Is the   |   |
| | or an EAD item      |---->| CRED via     |--->| retrieval   |   |
| | point to an already |     | ID_CRED_X or |    | of CRED     |   |
| | stored CRED?        |     | an EAD item  |    | successful? |   |
| +---------------------+     +--------------+    +-------------+   |
|         |                                        |          |     |
|         |                                        | NO       | YES |
|         |                         +--------------+          |     |
|         | YES                     |                         |     |
|         v                         v                         v     |
| +-----------------+ NO      +-----------+  YES +----------------+ |
| | 2. Is this CRED |-------->| 11. Abort |<-----| 5. Is the      | |
| | still valid?    |         | the EDHOC |      | used policy    | |
| +-----------------+         | session   |      | "NO-LEARNING"? | |
|         |                   |           |      +----------------+ |
|         | YES               |           |                   |     |
|         v                   |           |   The used policy | NO  |
| +--------------------+ NO   |           |   is "LEARNING"   |     |
| | 9. Is this CRED    |----->|           |                   v     |
| | good to use in the |      +-----------+         +-------------+ |
| | context of this    |               ^            | 6. Validate | |
| | EDHOC session?     |<--+           |            | CRED        | |
| +--------------------+   |           |            +-------------+ |
|         |                |           |                      |     |
|         | YES            |           | NO                   |     |
|         |                |           |                      v     |
|         |                |        +-----------------------------+ |
|         |                |        | 7. Is CRED valid?           | |
|         |                |        +-----------------------------+ |
|         |                |           |                            |
|         |                |           | YES                        |
|         |                |           v                            |
|         v                |        +-----------------------------+ |
| +------------------+     |        | 8. Store CRED as valid and  | |
| | 10. Continue by  |     +--------| trusted.                    | |
| | considering this |              |                             | |
| | CRED as the      |              | Pair CRED with consistent   | |
| | authentication   |              | credential identifiers, for | |
| | credential of    |              | each supported type of      | |
| | the other peer   |              | credential identifier.      | |
| +------------------+              +-----------------------------+ |
|         |                                                         |
+---------|---------------------------------------------------------+
          |
          |
+---------|---------------------------------------------------------+
|         |           Pre-verification side processing (PHASE_2)    |
|         v                                                         |
| +---------------------------------------------------------+       |
| | Process the EAD items that have not been processed yet, |       |
| | and that can be processed before message verification   |       |
| +---------------------------------------------------------+       |
|         |                                                         |
+---------|---------------------------------------------------------+
          |
          |

 Control transferred back
 to the core EDHOC processing

          |
          |
          v
 +------------------+
 | Verify message_X | (core EDHOC processing)
 +------------------+
          |
          |

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
| | available to build the next EDHOC message  |   |
| +--------------------------------------------+   |
|         |                                        |
+---------|----------------------------------------+
          |
          |

 Control transferred back
 to the core EDHOC processing

          |
          |
          v
 +----------------+
 | Advance the    | (core EDHOC processing)
 | protocol state |
 +----------------+
~~~~~~~~~~~
{: #fig-flowchart-spo-low-level title="Processing steps for EDHOC message_2 and message_3" artwork-align="center"}

# Security Considerations # {#sec-security-considerations}

TBD

# IANA Considerations

This document has no actions for IANA.

--- back

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -00 to -01 ## {#sec-00-01}

* Editorial improvements.

# Acknowledgments # {#acknowledgments}
{: numbered="no"}

The author sincerely thanks {{{Christian Amsüss}}}, {{{Geovane Fedrecheski}}}, {{{Rikard Höglund}}}, {{{John Preuß Mattsson}}}, {{{Göran Selander}}}, and {{{Mališa Vučinić}}} for their comments and feedback.

The work on this document has been partly supported by the Sweden's Innovation Agency VINNOVA and the Celtic-Next project CYPRESS.
