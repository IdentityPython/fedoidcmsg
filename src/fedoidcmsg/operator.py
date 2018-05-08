import json
import logging

from cryptojwt.exception import BadSignature
from cryptojwt.jws import JWSException
from oidcmsg.key_jar import KeyJar

from fedoidcmsg import ClientMetadataStatement
from fedoidcmsg import DoNotCompare
from fedoidcmsg import IgnoreKeys
from fedoidcmsg import MetadataStatementError
from fedoidcmsg import is_lesser
from fedoidcmsg import unfurl

from oidcmsg.exception import MissingSigningKey
from oidcmsg.oauth2 import Message
from oidcmsg.time_util import utc_time_sans_frac

__author__ = 'roland'

logger = logging.getLogger(__name__)


class ParseError(Exception):
    pass


class ParseInfo(object):
    def __init__(self):
        self.input = None
        self.parsed_statement = []
        self.error = {}
        self.result = None
        self.branch = {}
        self.keyjar = None
        self.signing_keys = None


class LessOrEqual(object):
    """
    Class in which to store the parse result from flattening a compounded
    metadata statement.
    """

    def __init__(self, iss='', sup=None, exp=0, keyjar=None, **kwargs):
        """
        :param iss: Issuer ID
        :param sup: Superior
        :type sup: LessOrEqual instance
        :param exp: Expiration time
        """
        if sup:
            self.fo = sup.fo
        else:
            self.fo = iss

        self.iss = iss
        self.sup = sup
        self.err = {}
        self.le = {}
        self.exp = exp
        self.keyjar = keyjar

    def __setitem__(self, key, value):
        self.le[key] = value

    def keys(self):
        return self.le.keys()

    def items(self):
        return self.le.items()

    def __getitem__(self, item):
        return self.le[item]

    def __contains__(self, item):
        return item in self.le

    def sup_items(self):
        """
        Items (key+values) from the superior        
        """
        if self.sup:
            return self.sup.le.items()
        else:
            return {}

    def eval(self, orig):
        """
        Apply the less or equal algorithm on the ordered list of metadata
        statements
        
        :param orig: Start values
        :return:
        """
        _le = {}
        _err = []
        for k, v in self.sup_items():
            if k in DoNotCompare:
                continue
            if k in orig:
                if is_lesser(orig[k], v):
                    _le[k] = orig[k]
                else:
                    _err.append({'claim': k, 'policy': orig[k], 'err': v,
                                 'signer': self.iss})
            else:
                _le[k] = v

        for k, v in orig.items():
            if k in DoNotCompare:
                continue
            if k not in _le:
                _le[k] = v

        self.le = _le
        self.err = _err

    def protected_claims(self):
        """
        Someone in the list of signers has said this information is OK
        """
        if self.sup:
            return self.sup.le

    def unprotected_and_protected_claims(self):
        """
        This is both verified and self asserted information. As expected 
        verified information beats self-asserted so if there is both 
        self-asserted and verified values for a claim then only the verified
        will be returned.
        """
        if self.sup:
            res = {}
            for k, v in self.le.items():
                if k not in self.sup.le:
                    res[k] = v
                else:
                    res[k] = self.sup.le[k]
            return res
        else:
            return self.le

    def is_expired(self):
        now = utc_time_sans_frac()
        if self.exp < now:
            return True
        if self.sup:
            return self.sup.is_expired()
        else:
            return False


def le_dict(les):
    return dict([(l.fo, l) for l in les])


def get_fo(ms):
    try:
        _mds = ms['metadata_statements']
    except KeyError:
        return ms['iss']
    else:
        # should only be one
        try:
            assert len(_mds) == 1
        except AssertionError:
            raise MetadataStatementError('Branching not allowed')

        _ms = list(_mds.values())[0]
        return get_fo(_ms)


class Operator(object):
    """
    An operator in a OIDC federation.
    """

    def __init__(self, self_signer=None, jwks_bundle=None, httpcli=None,
                 iss=None, lifetime=3600):
        """

        :param self_signer: A Signing Service instance
        :param jwks_bundle: Contains the federation operators signing keys
            for all the federations this instance wants to talk to.
            If present it MUST be a JWKSBundle instance.
        :param httpcli: A http client to use when information has to be
            fetched from somewhere else
        :param iss: Issuer ID
        :param lifetime: Default lifetime of signed statements produced
            by this signer.
        """
        self.self_signer = self_signer
        self.jwks_bundle = jwks_bundle
        self.httpcli = httpcli
        self.iss = iss
        self.failed = {}
        self.lifetime = lifetime

    def signing_keys_as_jwks(self):
        """
        Build a JWKS from the signing keys belonging to the self signer

        :return: Dictionary
        """
        _l = [x.serialize() for x in self.self_signer.keyjar.get_signing_key()]
        if not _l:
            _l = [x.serialize() for x in
                  self.self_signer.keyjar.get_signing_key(owner=self.iss)]
        return {'keys': _l}

    def signing_keys_as_jwks_json(self):
        return json.dumps(self.signing_keys_as_jwks())

    def _ums(self, pr, meta_s, keyjar):
        try:
            _pi = self.unpack_metadata_statement(
                jwt_ms=meta_s, keyjar=keyjar)
        except (JWSException, BadSignature,
                MissingSigningKey) as err:
            logger.error('Encountered: {}'.format(err))
            pr.error[meta_s] = err
        else:
            pr.branch[meta_s] = _pi
            if _pi.result:
                pr.parsed_statement.append(_pi.result)
                pr.signing_keys = _pi.signing_keys
        return pr

    def self_signed(self, ms_dict, jwt_ms, cls):
        kj = KeyJar()
        kj.import_jwks_as_json(ms_dict['signing_keys'], ms_dict['iss'])
        return cls().from_jwt(jwt_ms, keyjar=kj)

    def _unpack(self, ms_dict, keyjar, cls, jwt_ms=None, liss=None):
        """
        
        :param ms_dict: Metadata statement as a dictionary
        :param keyjar: A keyjar with the necessary FO keys
        :param cls: What class to map the metadata into
        :param jwt_ms: Metadata statement as a JWS 
        :param liss: List of FO issuer IDs
        :return: ParseInfo instance
        """
        if liss is None:
            liss = []

        _pr = ParseInfo()
        _pr.input = ms_dict
        ms_flag = False
        if 'metadata_statements' in ms_dict:
            ms_flag = True
            for iss, _ms in ms_dict['metadata_statements'].items():
                if liss and iss not in liss:
                    continue
                _pr = self._ums(_pr, _ms, keyjar)

        if 'metadata_statement_uris' in ms_dict:
            ms_flag = True
            if self.httpcli:
                for iss, url in ms_dict['metadata_statement_uris'].items():
                    if liss and iss not in liss:
                        continue
                    rsp = self.httpcli.http_request(url)
                    if rsp.status_code == 200:
                        _pr = self._ums(_pr, rsp.text, keyjar)
                    else:
                        raise ParseError(
                            'Could not fetch jws from {}'.format(url))

        for _ms in _pr.parsed_statement:
            if _ms:  # can be None
                loaded = False
                try:
                    keyjar.import_jwks_as_json(_ms['signing_keys'],
                                               ms_dict['iss'])
                except KeyError:
                    pass
                except TypeError:
                    try:
                        keyjar.import_jwks(_ms['signing_keys'], ms_dict['iss'])
                    except Exception as err:
                        logger.error(err)
                        raise
                    else:
                        loaded = True
                else:
                    loaded = True

                if loaded:
                    logger.debug(
                        'Loaded signing keys belonging to {} into the '
                        'keyjar'.format(ms_dict['iss']))

        if ms_flag is True and not _pr.parsed_statement:
            return _pr

        if jwt_ms:
            logger.debug("verifying signed JWT: {}".format(jwt_ms))
            try:
                _pr.result = cls().from_jwt(jwt_ms, keyjar=keyjar)
            except MissingSigningKey:
                if 'signing_keys' in ms_dict:
                    try:
                        _pr.result = self.self_signed(ms_dict, jwt_ms, cls)
                    except MissingSigningKey as err:
                        logger.error('Encountered: {}'.format(err))
                        _pr.error[jwt_ms] = err
            except (JWSException, BadSignature, KeyError) as err:
                logger.error('Encountered: {}'.format(err))
                _pr.error[jwt_ms] = err
        else:
            _pr.result = ms_dict

        if _pr.result and _pr.parsed_statement:
            _prr = _pr.result

            _res = {}
            for x in _pr.parsed_statement:
                if x:
                    _res[get_fo(x)] = x

            _msg = Message(**_res)
            logger.debug('Resulting metadata statement: {}'.format(_msg))
            _pr.result['metadata_statements'] = _msg
        return _pr

    def unpack_metadata_statement(self, ms_dict=None, jwt_ms='', keyjar=None,
                                  cls=ClientMetadataStatement, liss=None):
        """
        Starting with a signed JWT or a JSON document unpack and verify all
        the separate metadata statements.

        :param ms_dict: Metadata statement as a dictionary
        :param jwt_ms: Metadata statement as JWT
        :param keyjar: Keys that should be used to verify the signature of the
            document
        :param cls: What type (Class) of metadata statement this is
        :param liss: list of FO identifiers that matters. The rest will be 
            ignored
        :return: A ParseInfo instance
        """

        if not keyjar:
            if self.jwks_bundle:
                keyjar = self.jwks_bundle.as_keyjar()
            else:
                keyjar = KeyJar()

        if jwt_ms:
            try:
                ms_dict = unfurl(jwt_ms)
            except JWSException as err:
                logger.error('Could not unfurl jwt_ms due to {}'.format(err))
                raise

        if ms_dict:
            return self._unpack(ms_dict, keyjar, cls, jwt_ms, liss)
        else:
            raise AttributeError('Need one of ms_dict or jwt_ms')

    def pack_metadata_statement(self, metadata, receiver='', iss='', lifetime=0,
                                sign_alg=''):
        """
        Given a MetadataStatement instance create a signed JWT.

        :param metadata: Original metadata statement as a MetadataStatement
            instance
        :param receiver: Receiver (audience) of the JWT
        :param iss: Issuer ID if different from default
        :param lifetime: jWT signature life time
        :param sign_alg: JWT signature algorithm
        :return: A JWT
        """

        return self.self_signer.sign(metadata, receiver=receiver, iss=iss,
                                     lifetime=lifetime, sign_alg=sign_alg)

    def evaluate_metadata_statement(self, metadata, keyjar=None):
        """
        Computes the resulting metadata statement from a compounded metadata
        statement.
        If something goes wrong during the evaluation an exception is raised

        :param metadata: The compounded metadata statement as a dictionary
        :return: A list of :py:class:`fedoidc.operator.LessOrEqual` 
            instances, one per FO.
        """

        # start from the innermost metadata statement and work outwards

        res = dict([(k, v) for k, v in metadata.items() if k not in IgnoreKeys])

        les = []

        if 'metadata_statements' in metadata:
            for fo, ms in metadata['metadata_statements'].items():
                if isinstance(ms, str):
                    ms = json.loads(ms)
                for _le in self.evaluate_metadata_statement(ms):
                    if isinstance(ms, Message):
                        le = LessOrEqual(sup=_le, **ms.to_dict())
                    else:  # Must be a dict
                        le = LessOrEqual(sup=_le, **ms)

                    if le.is_expired():
                        logger.error(
                            'This metadata statement has expired: {}'.format(ms)
                        )
                        logger.info('My time: {}'.format(utc_time_sans_frac()))
                        continue
                    le.eval(res)
                    les.append(le)
            return les
        else:  # this is the innermost
            try:
                _iss = metadata['iss']
            except:
                le = LessOrEqual()
                le.eval(res)
            else:
                le = LessOrEqual(iss=_iss, exp=metadata['exp'])
                le.eval(res)
            les.append(le)
            return les

    def correct_usage(self, metadata, federation_usage):
        """
        Remove MS paths that are marked to be used for another usage

        :param metadata: Metadata statement as dictionary
        :param federation_usage: In which context this is expected to used.
        :return: Filtered Metadata statement.
        """

        if 'metadata_statements' in metadata:
            _msl = {}
            for fo, ms in metadata['metadata_statements'].items():
                if not isinstance(ms, Message):
                    ms = json.loads(ms)

                if self.correct_usage(ms, federation_usage=federation_usage):
                    _msl[fo] = ms
            if _msl:
                metadata['metadata_statements'] = Message(**_msl)
                return metadata
            else:
                return None
        else:  # this is the innermost
            try:
                assert federation_usage == metadata['federation_usage']
            except KeyError:
                pass
            except AssertionError:
                return None
            return metadata

    def extend_with_ms(self, req, sms_dict):
        """
        Add signed metadata statements to a request

        :param req: The request 
        :param sms_dict: A dictionary with FO IDs as keys and signed metadata
            statements (sms) or uris pointing to sms as values.
        :return: The updated request
        """
        _ms_uri = {}
        _ms = {}
        for fo, sms in sms_dict.items():
            if sms.startswith('http://') or sms.startswith('https://'):
                _ms_uri[fo] = sms
            else:
                _ms[fo] = sms

        if _ms:
            req['metadata_statements'] = Message(**_ms)
        if _ms_uri:
            req['metadata_statement_uris'] = Message(**_ms_uri)
        return req


class FederationOperator(Operator):
    def __init__(self, self_signer=None, jwks_bundle=None, httpcli=None,
                 iss=None, keyconf=None, bundle_sign_alg='RS256',
                 remove_after=86400):

        Operator.__init__(self, self_signer=self_signer,
                          jwks_bundle=jwks_bundle, httpcli=httpcli, iss=iss)

        self.keyconf = keyconf
        self.jb = jwks_bundle
        self.bundle_sign_alg = bundle_sign_alg
        self.remove_after = remove_after  # After this time inactive keys are
        # removed from the keyjar

    def add_to_bundle(self, fo, jwks):
        self.jb[fo] = jwks

    def remove_from_bundle(self, fo):
        del self.jb[fo]

    def export_bundle(self):
        return self.jb.create_signed_bundle(sign_alg=self.bundle_sign_alg)
