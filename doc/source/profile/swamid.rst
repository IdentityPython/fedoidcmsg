==================================================
The SWAMID profile for a OpenID Connect federation
==================================================

------------
Introduction
------------

This document describes how the Swedish Academic Identity Federation
(SWAMID) is planning to build an identity federation using OpenID Connect (`OIDC`_).
What is describe here is a profile of the `OIDC federation draft`_

.. _OIDC: http://openid.net/specs/openid-connect-core-1_0.html
.. _OIDC federation draft: http://openid.net/specs/openid-connect-federation-1_0.html

--------
Entities
--------

RP
    A Relying Party.
OP
    A OpenID Provider.
MDSS
    The Metadata Signing Service for the SWAMID Federation.
FO
    The Federation Operator

-----------------
Division of labor
-----------------

The FO handles the enrolment, verifies the correctness of the entity metadata statement
is responsible for any additions to the metadata that the FO process
demands (like adding entity_categories).

The MDSS gets processed metadata statements from the FO and deals with the signing
and distribution of the signed metadata statements.

-----------------------
The Federation operator
-----------------------

Is anyone that wants to create a multi lateral federation of RPs and OPs.

-------------------
The Signing Service
-------------------

The Signing Service is a key part of the architecture. Each federation MUST deploy one.
A Metadata Signing Service (MDSS) has control over the private part of the Federations signing key.

A MDSS will make the following public API calls available:

- GET */getsmscol/{context}/{entityID}*. Returns a signed JWT containing a
  collection of signed MS for *entityID* for a specific context *context*.

  This collection is a JSON object whose keys are federation IDs and the values are URLs where the
  corresponding Signed Metadata statements can be found.

 - Simple response example, where "https://swamid.sunet.se/" is the identifier
   of the FO and "https://rp.example.com/ms.jws" is the RP's entity ID::

    {
        "https://swamid.sunet.se/": "https://mdss.sunet.se/getsms/https%3A%2F%2Frp.example.com%2Fms.jws/https%3A%2F%2Fswamid.sunet.se%2F"
    }

- GET */getsms/{context}/{entityID}/{FO}*. Returns the Signed Metadata
  Statement as a signed JSON Web Token (`JWT`_) for *entityID* in the
  federation *FO* for context *context*.

------------------------------
Service provided by each RP/OP
------------------------------
Each RP/OP has to provide a web endpoint from which the entity's
metadata statement can be fetch. What's is returned from this endpoint is the
entity's metadata statement signed by the entity's signing key.

---------------------
The enrolment process
---------------------

Entities (RP/OP) can enrol to become part of the federation.
In the description below I will use an RP as the entity who wants
to enrol. If you want to enrol an OP, exactly the same process must
be followed.

The steps are

1 The entity sends

    - the public part of its signing key,
    - the URL the Federation Operator (FO) should use to fetch the entity's
      metadata statement and
    - an entity ID (for an OP this is the issuer ID). For an RP the entityID
      SHOULD be the URL mentioned above. The entity_id MUST be part of the
      metadata that an entity makes available to the FO.

2 The FO fetched the metadata statement, which is represented as a
  signed JWT, signed by the entity's private key, and verifies the signature.
  The public part of the entity's signing key are expected to be part
  of the metadata statement.
3 If the FO accepts the metadata statement as syntactically correct and
  adhering to the Federations policy it will add the payload of the
  signed metadata statement it received from the entity
  to the list of metadata statements that can be signed by the MDSS.
  Before it adds it to the list the FO may modify the metadata statement.

After this the FO will at intervals do (2). If nothing has
change in the metadata nothing more will happen. If something has changed
then the FO will do (3). It is assumed that the FO will quite frequently 
check for changes in the metadata.

------------------------------------
Using the signed metadata statements
------------------------------------

Once the RP has been accepted by the FO it can start acting within
the federation. This is what happens then:

1 When the RP needs to construct a client registration request it will
  ask the FO for the current set of Federations/Communities it belongs to.
  It does that by doing a GET on */getsmscol/{context}/{entityID}*.
  As shown above it will receive a JSON object with references to signed
  metadata statements. Now some claims in the client
  registration request may not be know before the RP knows which OP it talks to.
  That means that those claims will not be in the metadata statement that the
  FO signs.

  For instance, as a mitigation to a known security issue the *redirect_uris*
  should be unique per OP. An RP should in this case construct a metadata
  statement containing the extra claims together with the metadata statement
  references it received from the MDSS resulting in something like this::

    {
        'redirect_uris': ['https://rp.example.org/8670193851956608396'],
        'metadata_statement_uri': {
            "https://swamid.sunet.se/": "https://mdss.sunet.se/getsms/https%3A%2F%2Frp.example.com%2Fms.jws/https%3A%2F%2Fswamid.sunet.se%2F"
        }
    }

  And construct a signed `JWT`_ from this, signing it with its own
  signing key. Now the client registration request can be constructed as::

    {
        'redirect_uris': ['https://rp.example.org/8670193851956608396'],
        'metadata_statements': {
            "https://swamid.sunet.se/": 'eyJhbGciOiJFUzI1NiJ9.eyJyZWRpcmVjdF91cmlzIjogWyJodHRwczovL3JwLmV4YW1wbGUub3JnLzg2NzAxOTM4NTE5NTY2MDgzOTYiXSwgIm1ldGFkYXRhX3N0YXRlbWVudF91cmkiOiB7Imh0dHBzOi8vZm8uZXhhbXBsZS5lZHUvIjogImh0dHBzOi8vbWRzcy5mby5leGFtcGxlLmVkdS9nZXRtcy9odHRwcyUzQSUyRiUyRnJwLmV4YW1wbGUuY29tJTJGbXMuandzL2h0dHBzJTNBJTJGJTJGZm8uZXhhbXBsZS5lZHUlMkYifX0.y73e9d6Yr6JqaG9iss6GBcudFskHcRCBn6gYD8XW0TqS88b4ELh_G7M5GvTXbeDZ4wU7w-ZViP7srt1htG7HAQ'
        }
    }

  If the JSON object with the metadata references received from the FO contains
  more then one reference then the RP will have to construct one signed 
  metadata statement per reference.

2 When the OP receives the client registration request it can use the
  metadata_statements (which all contains metadata_statement_uris that points
  to the FOs MDSS) to find the metadata statements signed by the FO.

  The OP will do well to connect the issued client_id to the RPs entity_id.
  They can be the same or the client_id can be something derived from the 
  entity_id. This would allow the RP to keep the same client_id when the 
  RPs metadata changes.

-------------------------------------------------
What if the RP wants to change it's signing key ?
-------------------------------------------------

At some time after enrolment the RP wants to rotate it's signing key it will
have to do a new enrolment. There is no need at this point for the metadata
export URL or the entity_id to change.


.. _JWT : https://tools.ietf.org/html/rfc7519