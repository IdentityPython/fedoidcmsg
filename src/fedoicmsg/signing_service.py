import copy
import json
import logging
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import requests
from fedoicmsg import CONTEXTS
from fedoicmsg import MIN_SET
from fedoicmsg.file_system import FileSystem

from jwkest import as_unicode
from jwkest.jws import JWSException
from jwkest.jws import factory

from oicmsg.oauth2 import Message
from oicmsg.jwt import JWT

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

    def __call__(self, req, **kwargs):
        raise NotImplemented()

    def name(self):
        raise NotImplemented()


class InternalSigningService(SigningService):
    """
    A signing service that is internal to an entity
    """

    def __init__(self, iss, signing_keys, add_ons=None, alg='RS256',
                 lifetime=3600):
        """
        
        :param iss: The ID for this entity 
        :param signing_keys: Signing keys this entity can use to sign JWTs with.
        :param add_ons: Additional information the signing service must 
            add to the Metadata statement before signing it.
        :param alg: The signing algorithm
        :param lifetime: The lifetime of the signed JWT
        """
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.signing_keys = signing_keys
        self.iss = iss
        self.lifetime = lifetime

    def __call__(self, req, **kwargs):
        """

        :param req: Original metadata statement as a 
            :py:class:`MetadataStatement` instance
        :param keyjar: KeyJar in which the necessary keys should reside
        :param iss: Issuer ID
        :param alg: Which signing algorithm to use
        :param kwargs: Additional metadata statement attribute values
        :return: A JWT
        """
        iss = self.iss
        keyjar = self.signing_keys

        # Own copy
        _metadata = copy.deepcopy(req)
        if self.add_ons:
            _metadata.update(self.add_ons)

        _jwt = JWT(keyjar, iss=iss, msgtype=_metadata.__class__,
                   lifetime=self.lifetime)
        _jwt.sign_alg = self.alg

        if iss in keyjar.issuer_keys:
            owner = iss
        else:
            owner = ''

        if kwargs:
            return _jwt.pack(cls_instance=_metadata, owner=owner, **kwargs)
        else:
            return _jwt.pack(cls_instance=_metadata, owner=owner)

    def name(self):
        return self.iss


class WebSigningService(SigningService):
    """
    A client to a web base signing service.
    Uses HTTP Post to send the MetadataStatement to the service.
    """

    def __init__(self, iss, url, keyjar, add_ons=None, alg='RS256'):
        """

        :param iss: The issuer ID of the signer
        :param url: The URL of the signing service
        :param keyjar: A keyjar containing the public part of the signers key
        :param add_ons: Additional information the signing service must 
            add to the Metadata statement before signing it.
        :param alg: Signing algorithm 
        """
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.url = url
        self.iss = iss
        self.keyjar = keyjar

    def __call__(self, req, **kwargs):
        r = requests.post(self.url, json=req, verify=False)
        if 200 <= r.status_code < 300:
            _jw = factory(r.text)

            # First Just checking the issuer ID *not* verifying the Signature
            body = json.loads(as_unicode(_jw.jwt.part[1]))
            assert body['iss'] == self.iss

            # Now verifying the signature
            try:
                _jw.verify_compact(r.text,
                                   self.keyjar.get_verify_key(
                                       owner=self.iss))
            except AssertionError:
                raise JWSException('JWS signature verification error')

            return r.text
        else:
            raise SigningServiceError("{}: {}".format(r.status_code, r.text))

    def name(self):
        return self.url


class Signer(object):
    """
    A signer. Has no or one signing services it can use.
    Keeps a dictionary with the created signed metadata statements.
    """

    def __init__(self, signing_service=None, ms_dir=None, def_context=''):
        """
        
        :param signing_service: Which signing service this signer can use. 
        :param ms_dir: Where the file copies of the signed metadata statements
            are kept. Storing/retrieving the signed metadata statements are
            handled by :py:class:`fedoidc.file_system.FileSystem` instances.
            One per operations where they are expected to used.
        :param def_context: Default operation, one out of 
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
                    _sms = self.signing_service(req)
                    return {self.signing_service.iss: _sms}

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
                    _sms = self.signing_service(req)
                    return {self.signing_service.iss: _sms}

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

                    _sms = self.signing_service(req)
                else:
                    _sms = {}
                    for f in fos:
                        try:
                            val = cms[f]
                        except KeyError:
                            continue

                        if val.startswith('http'):
                            req['metadata_statement_uris'] = {f: val}
                            _sms[f] = self.signing_service(req)
                            del req['metadata_statement_uris']
                        else:
                            req['metadata_statements'] = {f: val}
                            _sms[f] = self.signing_service(req)
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
