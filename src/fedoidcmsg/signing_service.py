import copy
import json
import logging
import os
import time

import requests

from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from cryptojwt import as_unicode
from cryptojwt.jws import JWSException
from cryptojwt.jws import factory
from oidcmsg.key_jar import init_key_jar, build_keyjar

from fedoidcmsg import CONTEXTS
from fedoidcmsg import MIN_SET
from fedoidcmsg.file_system import FileSystem

from oidcmsg.oauth2 import Message
from oidcmsg.jwt import JWT

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
        """

        :param req: Original metadata statement as a 
            :py:class:`MetadataStatement` instance
        :param receiver: The intended audience for the JWS
        :param kwargs: Additional metadata statement attribute values
        :return: A dictionary with a signed JWT as value with the key 'sms'
        """
        iss = self.iss
        keyjar = self.keyjar

        # Own copy
        _metadata = copy.deepcopy(req)
        if self.add_ons:
            _metadata.update(self.add_ons)

        _jwt = JWT(keyjar, iss=iss, msg_cls=_metadata.__class__,
                   lifetime=self.lifetime)
        _jwt.sign_alg = self.alg

        if iss in keyjar.issuer_keys:
            owner = iss
        else:
            owner = ''

        if kwargs:
            sms = _jwt.pack(payload=_metadata.to_dict(), owner=owner,
                            recv=receiver, **kwargs)
        else:
            sms = _jwt.pack(payload=_metadata.to_dict(), owner=owner,
                            recv=receiver)

        return {'sms': sms}

    def name(self):
        return self.iss

    def public_keys(self):
        return self.keyjar.export_jwks()

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

    def export_jwks(self):
        return self.keyjar.export_jwks()

    def export_jwks_as_json(self):
        return self.keyjar.export_jwks_as_json()


class WebSigningServiceClient(SigningService):
    """
    A client to a web base signing service.
    Uses HTTP Post to send the MetadataStatement to the service.
    """

    def __init__(self, iss, url, id, keyjar, add_ons=None, alg='RS256',
            token='', token_type='Bearer', verify_ssl_cert=True):
        """

        :param iss: The issuer ID of the signer
        :param url: The URL of the signing service
        :param id: The identifier of this entity
        :param keyjar: A key jar containing the public part of the signers key
        :param add_ons: Additional information the signing service must 
            add to the Metadata statement before signing it.
        :param alg: Signing algorithm 
        """
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.url = url
        self.iss = iss
        self.id = id
        self.keyjar = keyjar
        self.token = token
        self.token_type = token_type
        self.verify_ssl_cert = verify_ssl_cert

    def parse_response(self, response):
        if 200 <= response.status_code < 300:
            _jw = factory(response.text)

            # First Just checking the issuer ID *not* verifying the Signature
            body = json.loads(as_unicode(_jw.jwt.part[1]))
            assert self.id in body['aud']

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
            _args = {'verify': self.verify_ssl_cert,
                     'auth': '{} {}'.format(self.token_type, self.token)}
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


class Signer(object):
    """
    A signer. Has one signing services it can use.
    Keeps a dictionary with the created signed metadata statements.
    """

    def __init__(self, signing_service=None, ms_dir=None, def_context=''):
        """
        
        :param signing_service: Which signing service this signer can use. 
        :param ms_dir: Where the file copies of the signed metadata statements
            are kept. Storing/retrieving the signed metadata statements are
            handled by :py:class:`fedoidc.file_system.FileSystem` instances.
            One per operations where they are expected to used.
        :param def_context: Default context, one out of
            :py:data:`fedoidc.CONTEXTS`
        """

        self.metadata_statements = {}

        if isinstance(ms_dir, dict):
            for key, _dir in ms_dir.items():
                if key not in CONTEXTS:
                    raise ValueError('{} not expected operation'.format(key))
                self.metadata_statements[key] = FileSystem(
                    _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        elif ms_dir:
            for item in os.listdir(ms_dir):
                if item not in CONTEXTS:
                    raise ValueError('{} not expected operation'.format(item))
                _dir = os.path.join(ms_dir, item)
                if os.path.isdir(_dir):
                    self.metadata_statements[item] = FileSystem(
                        _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        else:
            self.metadata_statements = MIN_SET

        self.signing_service = signing_service
        self.def_context = def_context

    def items(self):
        """
        Return a dictionary with contexts as keys and list of FOs as values.
        
        :rtype: list 
        """
        res = {}
        for key, fs in self.metadata_statements.items():
            res[key] = list(fs.keys())
        return res

    def metadata_statement_fos(self, context=''):
        """
        Get all the FOs that have signed metadata statements for a specific 
        context
        
        :param context: One of :py:data:`CONTEXTS` 
        :rtype: list
        """
        if not context:
            context = self.def_context

        try:
            return list(self.metadata_statements[context].keys())
        except KeyError:
            return []

    def create_signed_metadata_statement(self, req, context='', fos=None,
            single=False):
        """
        Gathers the metadata statements adds them to the request and signs
        the whole document.
        If *single* is **False** separate signed metadata statements will 
        be constructed per federation operator. If *single* is **True**
        only one signed metadata statement, containing all the signed
        metadata statements from all the federation operators, is created.
        
        :param req: The metadata statement to be signed
        :param context: The context in which this Signed metadata
            statement should be used
        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :param single: Should only a single signed metadata statement be
            returned or a set of such in a dictionary.
        :return: Dictionary with signed Metadata Statements as values
        """

        if not context:
            context = self.def_context

        _sms = None
        if self.metadata_statements:
            try:
                cms = self.metadata_statements[context]
            except KeyError:
                if self.metadata_statements == {'register': {},
                                                'discovery': {},
                                                'response': {}}:
                    # No superior so an FO then.
                    _res = self.signing_service.create(req)
                    return {self.signing_service.iss: _res['sms']}

                try:
                    logger.error(
                        'Signer: {}, items: {}'.format(self.signing_service.iss,
                                                       self.items()))
                except AttributeError:
                    raise SigningServiceError(
                        'This signer can not sign for that context')
                logger.error(
                    'No metadata statements for this context: {}'.format(
                        context))
                raise
            else:
                if cms == {}:
                    # No superior so a FO then.
                    _res = self.signing_service.create(req)
                    return {self.signing_service.iss: _res['sms']}

                if fos is None:
                    fos = list(cms.keys())

                if single:
                    for f in fos:
                        try:
                            val = cms[f]
                        except KeyError:
                            continue

                        if val.startswith('http'):
                            try:
                                req['metadata_statement_uris'][f] = val
                            except KeyError:
                                req['metadata_statement_uris'] = {f: val}
                        else:
                            try:
                                req['metadata_statements'][f] = val
                            except KeyError:
                                req['metadata_statements'] = {f: val}

                    _sms = self.signing_service.create(req)['sms']
                else:
                    _sms = {}
                    for f in fos:
                        try:
                            val = cms[f]
                        except KeyError:
                            continue

                        if val.startswith('http'):
                            req['metadata_statement_uris'] = {f: val}
                            _sms[f] = self.signing_service.create(req)['sms']
                            del req['metadata_statement_uris']
                        else:
                            req['metadata_statements'] = {f: val}
                            _sms[f] = self.signing_service.create(req)['sms']
                            del req['metadata_statements']

                if fos and not _sms:
                    raise KeyError('No metadata statements matched')

        return _sms

    def gather_metadata_statements(self, context='', fos=None):
        """
        Only gathers metadata statements and returns them.
        
        :param context: The context in which this Signed metadata
            statement should be used
        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :return: Dictionary with signed Metadata Statements as values
        """

        if not context:
            context = self.def_context

        _res = {}
        if self.metadata_statements:
            try:
                cms = self.metadata_statements[context]
            except KeyError:
                if self.metadata_statements == {'register': {},
                                                'discovery': {},
                                                'response': {}}:
                    # No superior so an FO then. Nothing to add ..
                    pass
                else:
                    logger.error(
                        'No metadata statements for this context: {}'.format(
                            context))
                    raise ValueError('Wrong context "{}"'.format(context))
            else:
                if cms != {}:
                    if fos is None:
                        fos = list(cms.keys())

                    for f in fos:
                        try:
                            val = cms[f]
                        except KeyError:
                            continue

                        if val.startswith('http'):
                            attr = 'metadata_statement_uris'
                        else:
                            attr = 'metadata_statements'

                        try:
                            _res[attr][f] = val
                        except KeyError:
                            _res[attr] = Message()
                            _res[attr][f] = val

        return _res


KJ_SPECS = ['private_path', 'key_defs', 'public_path']


def make_signing_service(config, entity_id):
    """
    Given configuration initiate a SigningService instance

    :param config: The signing service configuration
    :return: A SigningService instance
    """

    _args = dict([(k,v) for k,v in config.items() if k in KJ_SPECS])
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


def make_signer(config, entity_id):
    signing_service = make_signing_service(config['signing_service'],
                                           entity_id)

    try:
        sms_dir = config['ms_dir']
    except KeyError:
        msd = None
    else:
        if not os.path.isdir(sms_dir):
            os.makedirs(sms_dir)

        try:
            _ctx = config['contexts']
        except KeyError:
            _ctx = ['registration', 'discovery', 'response']

        msd = {}
        for _c in _ctx:
            _path = os.path.join(sms_dir, _c)
            if not os.path.isdir(_path):
                os.mkdir(_path)
            msd[_c] = _path

    signer = Signer(signing_service, msd)
    try:
        signer.def_context = config['def_context']
    except KeyError:
        pass

    return signer
