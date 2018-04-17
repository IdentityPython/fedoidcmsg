import json

from cryptojwt import as_unicode
from cryptojwt.jws import alg2keytype
from cryptojwt.jws import JWS
from cryptojwt.jws import factory

from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import jwks_to_keyjar

from oidcmsg.oidc import JsonWebToken
from oidcmsg.jwt import JWT


def self_sign_jwks(keyjar, iss, kid='', lifetime=3600):
    """
    Create a signed JWT containing a JWKS. The JWT is signed by one of the
    keys in the JWKS.

    :param keyjar: A KeyJar instance with at least one private signing key
    :param iss: issuer of the JWT, should be the owner of the keys
    :param kid: A key ID if a special key should be used otherwise one
        is picked at random.
    :param lifetime: The lifetime of the signed JWT
    :return: A signed JWT
    """

    # _json = json.dumps(jwks)
    _jwt = JWT(keyjar, iss=iss, lifetime=lifetime)

    jwks = keyjar.export_jwks(issuer=iss)

    return _jwt.pack(payload={'jwks': jwks}, owner=iss, kid=kid)


def verify_self_signed_jwks(sjwt):
    """
    Verify the signature of a signed JWT containing a JWKS.
    The JWT is signed by one of the keys in the JWKS. 
    In the JWT the JWKS is stored using this format ::
    
        'jwks': {
            'keys': [ ]
        }

    :param sjwt: Signed Jason Web Token
    :return: Dictionary containing 'jwks' (the JWKS) and 'iss' (the issuer of 
        the JWT)
    """

    _jws = factory(sjwt)
    _json = _jws.jwt.part[1]
    _body = json.loads(as_unicode(_json))
    iss = _body['iss']
    _jwks = _body['jwks']

    _kj = jwks_to_keyjar(_jwks, iss)

    try:
        _kid = _jws.jwt.headers['kid']
    except KeyError:
        _keys = _kj.get_signing_key(owner=iss)
    else:
        _keys = _kj.get_signing_key(owner=iss, kid=_kid)

    _ver = _jws.verify_compact(sjwt, _keys)
    return {'jwks': _ver['jwks'], 'iss': iss}


def request_signed_by_signing_keys(keyjar, msreq, iss, lifetime, kid=''):
    """
    A metadata statement signing request with 'signing_keys' signed by one
    of the keys in 'signing_keys'.

    :param keyjar: A KeyJar instance with the private signing key
    :param msreq: Metadata statement signing request. A MetadataStatement 
        instance.
    :param iss: Issuer of the signing request also the owner of the signing 
        keys.
    :return: Signed JWT where the body is the metadata statement
    """

    try:
        jwks_to_keyjar(msreq['signing_keys'], iss)
    except KeyError:
        jwks = keyjar.export_jwks(issuer=iss)
        msreq['signing_keys'] = jwks

    _jwt = JWT(keyjar, iss=iss, lifetime=lifetime)

    return _jwt.pack(owner=iss, kid=kid, payload=msreq.to_dict())


def verify_request_signed_by_signing_keys(smsreq):
    """
    Verify that a JWT is signed with a key that is inside the JWT.
    
    :param smsreq: Signed Metadata Statement signing request
    :return: Dictionary containing 'ms' (the signed request) and 'iss' (the
        issuer of the JWT).
    """

    _jws = factory(smsreq)
    _json = _jws.jwt.part[1]
    _body = json.loads(as_unicode(_json))
    iss = _body['iss']
    _jwks = _body['signing_keys']

    _kj = jwks_to_keyjar(_jwks, iss)

    try:
        _kid = _jws.jwt.headers['kid']
    except KeyError:
        _keys = _kj.get_signing_key(owner=iss)
    else:
        _keys = _kj.get_signing_key(owner=iss, kid=_kid)

    _ver = _jws.verify_compact(smsreq, _keys)
    # remove the JWT specific claims
    for k in JsonWebToken.c_param.keys():
        try:
            del _ver[k]
        except KeyError:
            pass
    try:
        del _ver['kid']
    except KeyError:
        pass

    return {'ms': MetadataStatement(**_ver), 'iss': iss}


def get_signing_keys(claims, keyjar, httpcli):
    if 'signed_jwks_uri' not in claims:
        return None

    res = httpcli.get(claims['signed_jwks_uri'])

    if res.status == 200:
        _jws = JWS()


def store_signed_jwks(keyjar, sign_keyjar, path, alg, iss=''):
    _jwks = keyjar.export_jwks()
    _jws = JWS(_jwks, alg=alg)
    _jwt = _jws.sign_compact(
        sign_keyjar.get_signing_key(owner=iss, key_type=alg2keytype(alg)))
    fp = open(path, 'w')
    fp.write(_jwt)
    fp.close()


def replace_jwks_key_bundle(keyjar, owner, new_kb):
    try:
        kbl = keyjar.issuer_keys[owner]
    except KeyError:
        pass
    else:
        res = [new_kb]
        for kb in kbl:
            if kb.imp_jwks is None:
                res.append(kb)
        keyjar.issuer_keys[owner] = res
