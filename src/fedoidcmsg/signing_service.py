import copy
import json
import logging
import time

import requests
from cryptojwt import as_unicode
from cryptojwt.jws import JWSException
from cryptojwt.jws import factory
from oidcmsg.jwt import JWT
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import init_key_jar

from fedoidcmsg import NoSigningKeys

logger = logging.getLogger(__name__)


class SigningServiceError(Exception):
    pass


class SigningService(object):
    """
    A service that can sign a :py:class:`fedoidc.MetadataStatement` instance
    """

    def __init__(self, add_ons=None, alg='RS256'):
        self.add_ons = add_ons or {}
        self.alg = alg

    def create(self, req, **kwargs):
        raise NotImplemented()

    def name(self):
        raise NotImplemented()


class InternalSigningService(SigningService):
    """
    A signing service that is internal to an entity
    """

    def __init__(self, iss, keyjar, add_ons=None, alg='RS256',
                 lifetime=3600, keyconf=None, remove_after=86400):
        """
        
        :param iss: The ID for this entity 
        :param keyjar: Signing keys this entity can use to sign JWTs with.
        :param add_ons: Additional information the signing service must 
            add to the Metadata statement before signing it.
        :param alg: The signing algorithm
        :param lifetime: The lifetime of the signed JWT
        """
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.keyjar = keyjar
        self.iss = iss
        self.lifetime = lifetime
        self.keyconf = keyconf
        self.remove_after = remove_after

    def create(self, req, receiver='', **kwargs):
        return self.sign(req=req, receiver=receiver, **kwargs)

    def sign_and_encrypt(self, req, receiver='', iss='', lifetime=0,
                         sign_alg='', enc_enc="A128CBC-HS256", enc_alg="RSA1_5"):

        return self.pack(req=req, receiver=receiver, iss=iss, lifetime=lifetime,
                         sign=True, sign_alg=sign_alg, encrypt=True,
                         enc_enc=enc_enc, enc_alg=enc_alg)

    def sign(self, req, receiver='', iss='', lifetime=0, sign_alg=''):
        """
        Creates a signed JWT

        :param req: Original metadata statement as a
            :py:class:`MetadataStatement` instance
        :param receiver: The intended audience for the JWS
        :param iss: Issuer or the JWT
        :param lifetime: Lifetime of the signature
        :param sign_alg: Which signature algorithm to use
        :return: A signed JWT
        """
        if not sign_alg:
            for key_type, s_alg in [('RSA', 'RS256'), ('EC', 'ES256')]:
                if self.keyjar.get_signing_key(key_type=key_type):
                    sign_alg = s_alg
                    break

        if not sign_alg:
            raise NoSigningKeys('Could not find any signing keys')

        return self.pack(req=req, receiver=receiver, iss=iss, lifetime=lifetime,
                         sign=True, encrypt=False, sign_alg=sign_alg)

    def encrypt(self, req, receiver='', iss='', lifetime=0,
                enc_enc="A128CBC-HS256", enc_alg="RSA1_5"):
        """

        :param req: Original metadata statement as a
            :py:class:`MetadataStatement` instance
        :param receiver: The intended audience for the JWS
        :param iss:
        :param lifetime:
        :param enc_alg:
        :param enc_enc:
        :return: A dictionary with a signed JWT as value with the key 'sms'
        """

        return self.pack(req=req, receiver=receiver, iss=iss, lifetime=lifetime,
                          sign=False, encrypt=True, enc_enc=enc_enc,
                         enc_alg=enc_alg)

    def pack(self, req, receiver='', iss='', lifetime=0, sign=True,
             sign_alg='', encrypt=False, enc_enc="A128CBC-HS256",
             enc_alg="RSA1_5"):
        """

        :param req: Original metadata statement as a 
            :py:class:`MetadataStatement` instance
        :param receiver: The intended audience for the JWS
        :param iss:
        :param lifetime:
        :param sign:
        :param sign_alg:
        :param encrypt:
        :param enc_alg:
        :param enc_enc:
        :return: A dictionary with a signed JWT as value with the key 'sms'
        """
        if not iss:
            iss = self.iss
        if not lifetime:
            lifetime = self.lifetime

        keyjar = self.keyjar

        # Own copy
        _metadata = copy.deepcopy(req)
        if self.add_ons:
            _metadata.update(self.add_ons)

        args = {}
        if sign:
            if sign_alg:
                args['sign_alg'] = sign_alg
            else:
                args['sign_alg'] = self.alg
        if encrypt:
            args['enc_enc'] = enc_enc
            args['enc_alg'] = enc_alg

        _jwt = JWT(keyjar, iss=iss, msg_cls=_metadata.__class__,
                   lifetime=lifetime, **args)
        # _jwt.sign_alg = self.alg

        if iss in keyjar.issuer_keys:
            owner = iss
        else:
            owner = ''

        return _jwt.pack(payload=_metadata.to_dict(), owner=owner,
                         recv=receiver)

    def name(self):
        return self.iss

    def public_keys(self):
        try:
            return self.keyjar.export_jwks()
        except KeyError:
            return self.keyjar.export_jwks(issuer=self.iss)

    def rotate_keys(self, keyconf=None):
        _old = [k.kid for k in self.keyjar.get_issuer_keys('') if k.kid]

        if keyconf:
            self.keyjar = build_keyjar(keyconf, keyjar=self.keyjar)[1]
        elif self.keyconf:
            self.keyjar = build_keyjar(self.keyconf, keyjar=self.keyjar)[1]
        else:
            logger.info("QWas asked to rotate key but could not comply")
            return

        self.keyjar.remove_after = self.remove_after
        self.keyjar.remove_outdated()

        _now = time.time()
        for k in self.keyjar.get_issuer_keys(''):
            if k.kid in _old:
                if not k.inactive_since:
                    k.inactive_since = _now

    def export_jwks_as_json(self):
        try:
            return self.keyjar.export_jwks_as_json()
        except KeyError:
            return self.keyjar.export_jwks_as_json(issuer=self.iss)


class WebSigningServiceClient(SigningService):
    """
    A client to a web base signing service.
    Uses HTTP Post to send the MetadataStatement to the service.
    """

    def __init__(self, iss, url, eid, keyjar, add_ons=None, alg='RS256',
                 token='', token_type='Bearer', verify_ssl_cert=True):
        """

        :param iss: The issuer ID of the signer
        :param url: The URL of the signing service
        :param eid: The identifier of this entity
        :param keyjar: A key jar containing the public part of the signers key
        :param add_ons: Additional information the signing service must 
            add to the Metadata statement before signing it.
        :param alg: Signing algorithm 
        """
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.url = url
        self.iss = iss
        self.eid = eid
        self.keyjar = keyjar
        self.token = token
        self.token_type = token_type
        self.verify_ssl_cert = verify_ssl_cert

    def parse_response(self, response):
        if 200 <= response.status_code < 300:
            _jw = factory(response.text)

            # First Just checking the issuer ID *not* verifying the Signature
            body = json.loads(as_unicode(_jw.jwt.part[1]))
            assert self.eid in body['aud']

            # Now verifying the signature
            try:
                _jw.verify_compact(response.text,
                                   self.keyjar.get_verify_key(
                                       owner=self.iss))
            except AssertionError:
                raise JWSException('JWS signature verification error')

            location = response.headers['Location']

            return {'sms': response.text, 'loc': location}
        else:
            raise SigningServiceError("{}: {}".format(response.status_code,
                                                      response.text))

    def req_args(self):
        if self.token:
            _args = {
                'verify': self.verify_ssl_cert,
                'auth': '{} {}'.format(self.token_type, self.token)
            }
        else:
            _args = {'verify': self.verify_ssl_cert}
        return _args

    def create(self, req, **kwargs):
        """
        Uses POST to send a first metadata statement signing request to
        a signing service.

        :param req: The metadata statement that the entity wants signed
        :return: returns a dictionary with 'sms' and 'loc' as keys.
        """

        response = requests.post(self.url, json=req, **self.req_args())
        return self.parse_response(response)

    def name(self):
        return self.url

    def update_metadata_statement(self, location, req):
        """
        Uses PUT to update an earlier accepted and signed metadata statement.

        :param location: A URL to which the update request is sent
        :param req: The diff between what is registereed with the signing
            service and what it should be.
        :return: returns a dictionary with 'sms' and 'loc' as keys.
        """
        response = requests.put(location, json=req, **self.req_args())
        return self.parse_response(response)

    def update_signature(self, location):
        """
        Uses GET to get a newly signed metadata statement.

        :param location: A URL to which the request is sent
        :return: returns a dictionary with 'sms' and 'loc' as keys.
        """
        response = requests.get(location, **self.req_args())
        return self.parse_response(response)


KJ_SPECS = ['private_path', 'key_defs', 'public_path']


def make_internal_signing_service(config, entity_id):
    """
    Given configuration initiate an InternalSigningService instance

    :param config: The signing service configuration
    :param entity_id: The entity identifier
    :return: A InternalSigningService instance
    """

    _args = dict([(k, v) for k, v in config.items() if k in KJ_SPECS])
    _kj = init_key_jar(**_args)

    return InternalSigningService(entity_id, _kj)


def make_signing_service(config, entity_id):
    """
    Given configuration initiate a SigningService instance

    :param config: The signing service configuration
    :param entity_id: The entity identifier
    :return: A SigningService instance
    """

    _args = dict([(k, v) for k, v in config.items() if k in KJ_SPECS])
    _kj = init_key_jar(**_args)

    if config['type'] == 'internal':
        signer = InternalSigningService(entity_id, _kj)
    elif config['type'] == 'web':
        _kj.issuer_keys[config['iss']] = _kj.issuer_keys['']
        del _kj.issuer_keys['']
        signer = WebSigningServiceClient(config['iss'], config['url'],
                                         entity_id, _kj)
    else:
        raise ValueError('Unknown signer type: {}'.format(config['type']))

    return signer
