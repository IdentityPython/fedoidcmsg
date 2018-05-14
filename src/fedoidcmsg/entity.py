import copy
import json
import logging
import os
import re
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from oidcmsg.key_jar import init_key_jar
from oidcmsg.message import Message
from oidcmsg.oidc import JsonWebToken

from fedoidcmsg import CONTEXTS
from fedoidcmsg import MIN_SET
from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import FSJWKSBundle
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.file_system import FileSystem
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import KJ_SPECS
from fedoidcmsg.signing_service import make_internal_signing_service

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(Operator):
    """
    An entity in a federation. For instance an OP or an RP.
    """

    def __init__(self, srv, iss='', signer=None, self_signer=None,
                 fo_bundle=None, context='', entity_id='',
                 fo_priority=None):
        """

        :param srv: A Client or Provider instance
        :param iss: A identifier assigned to this entity by the operator
        :param self_signer: Signer this entity can use to sign things
        :param signer: A signer to use for signing documents
            (client registration requests/provide info response) this
            entity produces.
        :param fo_bundle: A bundle of keys that can be used to verify
            the root signature of a compounded metadata statement.
        """

        Operator.__init__(self, self_signer=self_signer, iss=iss, httpcli=srv,
                          jwks_bundle=fo_bundle)

        # Who can sign request from this entity
        self.signer = signer
        self.federation = None
        self.context = context
        self.entity_id = entity_id
        self.fo_priority = fo_priority or []
        self.provider_federations = None
        self.registration_federations = None

    @staticmethod
    def pick_by_priority(ms_list, priority=None):
        if not priority:
            return ms_list[0]  # Just return any

        for iss in priority:
            for ms in ms_list:
                if ms.iss == iss:
                    return ms

        return None

    def pick_signed_metadata_statements_regex(self, pattern, context):
        """
        Pick signed metadata statements based on ISS pattern matching
        
        :param pattern: A regular expression to match the iss against
        :return: list of tuples (FO ID, signed metadata statement)
        """
        comp_pat = re.compile(pattern)
        sms_dict = self.signer.metadata_statements[context]
        res = []
        for iss, vals in sms_dict.items():
            if comp_pat.search(iss):
                res.extend((iss, vals))
        return res

    def pick_signed_metadata_statements(self, fo, context):
        """
        Pick signed metadata statements based on ISS pattern matching
        
        :param fo: Federation operators ID
        :param context: In connect with which operation (one of the values in 
            :py:data:`fedoidc.CONTEXTS`). 
        :return: list of tuples (FO ID, signed metadata statement)
        """
        sms_dict = self.signer.metadata_statements[context]
        res = []
        for iss, vals in sms_dict.items():
            if iss == fo:
                res.extend((iss, vals))
        return res

    def get_metadata_statement(self, input, cls=MetadataStatement,
                               context=''):
        """
        Unpack and evaluate a compound metadata statement. Goes through the
        necessary three steps.
        * unpack the metadata statement
        * verify that the given statements are expected to be used in this context
        * evaluate the metadata statements (= flatten)

        :param input: The metadata statement as a JSON document or a
            dictionary
        :param cls: The class the response should be typed into
        :param context: In which context the metadata statement should be used.
        :return: A list of :py:class:`fedoidc.operator.LessOrEqual` instances
        """
        logger.debug('Incoming metadata statement: {}'.format(input))

        if isinstance(input, dict):
            data = input
        else:
            if isinstance(input, Message):
                data = input.to_dict()
            else:
                data = json.loads(input)

        _pi = self.unpack_metadata_statement(ms_dict=data, cls=cls)
        if not _pi.result:
            return []

        logger.debug('Managed to unpack the metadata statement')

        if context:
            _cms = self.correct_usage(_pi.result, context)
        else:
            _cms = _pi.result

        logger.debug('After filtering for correct usage: {}'.format(_cms))

        if _cms:
            return self.evaluate_metadata_statement(_cms)
        else:
            return []

    def add_signing_keys(self, statement):
        """
        Adding signing keys by value to a statement.

        :param statement: Metadata statement to be extended
        :return: The extended statement
        """
        statement['signing_keys'] = self.self_signer.export_jwks_as_json()
        return statement

    def add_sms_spec_to_request(self, req, federation='', loes=None,
                                context=''):
        return req

    def update_metadata_statement(self, req):
        return req


class FederationEntityOOB(FederationEntity):
    """
    An entity in a OOB federation. For instance an OP or an RP.
    """

    def __init__(self, srv, iss='', signer=None, self_signer=None,
                 fo_bundle=None, sms_dir='', context='', entity_id='',
                 fo_priority=None):
        FederationEntity.__init__(self, srv, iss, signer=signer,
                                  self_signer=self_signer, fo_bundle=fo_bundle,
                                  context=context, entity_id=entity_id,
                                  fo_priority=fo_priority)

        self.metadata_statements = {}

        if isinstance(sms_dir, dict):
            for key, _dir in sms_dir.items():
                if key not in CONTEXTS:
                    raise ValueError('{} not expected operation'.format(key))
                self.metadata_statements[key] = FileSystem(
                    _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        elif sms_dir:
            for item in os.listdir(sms_dir):
                if item not in CONTEXTS:
                    raise ValueError('{} not expected operation'.format(item))
                _dir = os.path.join(sms_dir, item)
                if os.path.isdir(_dir):
                    self.metadata_statements[item] = FileSystem(
                        _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        else:
            self.metadata_statements = copy.deepcopy(MIN_SET)

    def add_sms_spec_to_request(self, req, federation='', loes=None,
                                context=''):
        """
        Update a request with signed metadata statements.
        
        :param req: The request 
        :param federation: Federation Operator ID
        :param loes: List of :py:class:`fedoidc.operator.LessOrEqual` instances
        :param context:
        :return: The updated request
        """
        if federation:  # A specific federation or list of federations
            if isinstance(federation, list):
                req.update(self.gather_metadata_statements(federation,
                                                           context=context))
            else:
                req.update(self.gather_metadata_statements([federation],
                                                           context=context))
        else:  # All federations I belong to
            if loes:
                _fos = list([r.fo for r in loes])
                req.update(self.gather_metadata_statements(_fos,
                                                           context=context))
            else:
                req.update(self.gather_metadata_statements(context=context))

        return req

    def self_sign(self, req, receiver=''):
        """
        Sign the extended request.
        
        :param req: Request, a :py:class:`fedoidcmsg.MetadataStatement' instance
        :param receiver: The intended user of this metadata statement
        :return: An augmented set of request arguments
        """
        if self.entity_id:
            _iss = self.entity_id
        else:
            _iss = self.iss

        creq = req.copy()
        if not 'metadata_statement_uris' in creq and not \
                'metadata_statements' in creq:
            _copy = creq.copy()
            _jws = self.self_signer.sign(_copy, receiver=receiver, iss=_iss)
            sms_spec = {'metadata_statements': {self.iss: _jws}}
        else:
            for ref in ['metadata_statement_uris', 'metadata_statements']:
                try:
                    del creq[ref]
                except KeyError:
                    pass

            sms_spec = {}
            for ref in ['metadata_statement_uris', 'metadata_statements']:
                if ref not in req:
                    continue
                sms_spec[ref] = Message()

                for foid, value in req[ref].items():
                    _copy = creq.copy()
                    _copy[ref] = MetadataStatement()
                    _copy[ref][foid] = value
                    _jws = self.self_signer.sign(_copy, receiver=receiver,
                                                 iss=_iss)
                    sms_spec[ref][foid] = _jws

        creq.update(sms_spec)
        return creq

    def gather_metadata_statements(self, fos=None, context=''):
        """
        Only gathers metadata statements and returns them.

        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :param context: context of the metadata exchange
        :return: Dictionary with signed Metadata Statements as values
        """

        if not context:
            context = self.context

        _res = {}
        if self.metadata_statements:
            try:
                cms = self.metadata_statements[context]
            except KeyError:
                if self.metadata_statements == {
                    'register': {},
                    'discovery': {},
                    'response': {}
                }:
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
                            value_type = 'metadata_statement_uris'
                        else:
                            value_type = 'metadata_statements'

                        try:
                            _res[value_type][f] = val
                        except KeyError:
                            _res[value_type] = Message()
                            _res[value_type][f] = val

        return _res

    def update_metadata_statement(self, metadata_statement, receiver='',
                                  federation=None, context=''):
        """
        Update a metadata statement by:
         * adding signed metadata statements or uris pointing to signed
           metadata statements.
         * adding the entities signing keys
         * create metadata statements one per signed metadata statement or uri
           sign these and add them to the metadata statement

        :param metadata_statement: A :py:class:`fedoidcmsg.MetadataStatement`
            instance
        :param receiver: The intended receiver of the metadata statement
        :param federation:
        :param context:
        :return: An augmented metadata statement
        """
        self.add_sms_spec_to_request(metadata_statement, federation=federation,
                                     context=context)
        self.add_signing_keys(metadata_statement)
        metadata_statement = self.self_sign(metadata_statement, receiver)
        # These are unprotected here so can as well be removed
        del metadata_statement['signing_keys']
        return metadata_statement


class FederationEntityAMS(FederationEntity):
    """
    An entity in a AMS federation. For instance an OP or an RP.
    """

    def __init__(self, srv, iss='', signer=None, self_signer=None,
                 fo_bundle=None, mds_service='', context='', entity_id='',
                 fo_priority=None, mds_owner=''):
        FederationEntity.__init__(self, srv, iss, signer=signer,
                                  self_signer=self_signer, fo_bundle=fo_bundle,
                                  context=context, entity_id=entity_id,
                                  fo_priority=fo_priority)

        self.mds_service = mds_service
        self.mds_owner = mds_owner

    def add_sms_spec_to_request(self, req, federation='', loes=None,
                                context='', url=''):
        """
        Add signed metadata statements to the request

        :param req: The request so far
        :param federation: If only signed metadata statements from a specific
            set of federations should be included this is the set.
        :param loes: - not used -
        :param context: What kind of request/response it is: 'registration',
            'discovery' or 'response'. The later being registration response.
        :param url: Just for testing !!
        :return: A possibly augmented request.
        """
        # fetch the signed metadata statement collection

        if federation:
            if not isinstance(federation, list):
                federation = [federation]

        if not url:
            url = "{}/getms/{}/{}".format(self.mds_service, context,
                                          self.entity_id)

        http_resp = self.httpcli('GET', url)

        if http_resp.status_code >= 400:
            raise ConnectionError('HTTP Error: {}'.format(http_resp.text))

        # verify signature on response
        msg = JsonWebToken().from_jwt(http_resp.text,
                                      keyjar=self.jwks_bundle[self.mds_owner])

        if msg['iss'] != self.mds_owner:
            raise KeyError('Wrong iss')

        if federation:
            _ms = dict(
                [(fo, _ms) for fo, _ms in msg.items() if fo in federation])
        else:
            _ms = msg.extra()
            try:
                del _ms['kid']
            except KeyError:
                pass

        _sms = {}
        _smsu = {}
        for fo, item in _ms.items():
            if item.startswith('https://') or item.startswith('http://'):
                _smsu[fo] = item
            else:
                _sms[fo] = item

        if _sms:
            req.update({'signed_metadata_statements': _sms})
        if _smsu:
            req.update({'signed_metadata_statement_uris': _smsu})

        return req


class FederationEntitySwamid(FederationEntity):
    """
    An entity in a SWAMID type federation. For instance an OP or an RP.
    """

    def __init__(self, srv, iss='', signer=None, self_signer=None,
                 fo_bundle=None, mdss_endpoint='', context='', entity_id='',
                 fo_priority=None, mds_owner=''):
        FederationEntity.__init__(self, srv, iss, signer=signer,
                                  self_signer=self_signer, fo_bundle=fo_bundle,
                                  context=context, entity_id=entity_id,
                                  fo_priority=fo_priority)

        self.mdss_endpoint = mdss_endpoint
        self.mds_owner = mds_owner

    def add_sms_spec_to_request(self, req, federation='', loes=None,
                                context='', url=''):
        """
        Add signed metadata statements to the request

        :param req: The request so far
        :param federation: If only signed metadata statements from a specific
            set of federations should be included this is the set.
        :param loes: - not used -
        :param context: What kind of request/response it is: 'registration',
            'discovery' or 'response'. The later being registration response.
        :param url: Just for testing !!
        :return: A possibly augmented request.
        """
        # fetch the signed metadata statement collection

        if federation:
            if not isinstance(federation, list):
                federation = [federation]

        if not url:
            url = "{}/getsmscol/{}/{}".format(self.mdss_endpoint, context,
                                              self.entity_id)

        http_resp = self.httpcli('GET', url)

        if http_resp.status_code >= 400:
            raise ConnectionError('HTTP Error: {}'.format(http_resp.text))

        msg = JsonWebToken().from_jwt(http_resp.text,
                                      keyjar=self.jwks_bundle[self.mds_owner])

        if msg['iss'] != self.mds_owner:
            raise KeyError('Wrong iss')

        if federation:
            _sms = dict(
                [(fo, _ms) for fo, _ms in msg.items() if fo in federation])
        else:
            _sms = msg.extra()
            try:
                del _sms['kid']
            except KeyError:
                pass

        req.update({'signed_metadata_statement_uris': _sms})
        return req


def make_federation_entity(config, eid='', httpcli=None):
    """
    Construct a :py:class:`fedoidcmsg.entity.FederationEntity` instance based
    on given configuration.

    :param config: Federation entity configuration
    :param eid: Entity ID
    :param httpcli: A http client instance to use when sending HTTP requests
    :return: A :py:class:`fedoidcmsg.entity.FederationEntity` instance
    """
    args = {}

    if not eid:
        try:
            eid = config['entity_id']
        except KeyError:
            pass

    if 'self_signer' in config:
        self_signer = make_internal_signing_service(config['self_signer'],
                                                    eid)
        args['self_signer'] = self_signer

    try:
        bundle_cnf = config['fo_bundle']
    except KeyError:
        pass
    else:
        _args = dict([(k, v) for k, v in bundle_cnf.items() if k in KJ_SPECS])
        if _args:
            _kj = init_key_jar(**_args)
        else:
            _kj = None

        if 'dir' in bundle_cnf:
            jb = FSJWKSBundle(eid, _kj, bundle_cnf['dir'],
                              key_conv={'to': quote_plus, 'from': unquote_plus})
        else:
            jb = JWKSBundle(eid, _kj)
        args['fo_bundle'] = jb

    for item in ['context', 'entity_id', 'fo_priority', 'mds_owner']:
        try:
            args[item] = config[item]
        except KeyError:
            pass

    # These are mutually exclusive
    if 'sms_dir' in config:
        args['sms_dir'] = config['sms_dir']
        return FederationEntityOOB(httpcli, iss=eid, **args)
    elif 'mds_service' in config:
        args['mds_service'] = config['mds_service']
        return FederationEntityAMS(httpcli, iss=eid, **args)
    elif 'mdss_endpoint' in config:
        args['mdss_endpoint'] = config['mdss_endpoint']
        return FederationEntitySwamid(httpcli, iss=eid, **args)
