import logging
import re

from fedoidcmsg import MetadataStatement
from fedoidcmsg.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(Operator):
    """
    An entity in a federation. For instance an OP or an RP.
    """

    def __init__(self, srv, iss='', keyjar=None, signer=None, fo_bundle=None):
        """

        :param srv: A Client or Provider instance
        :param iss: A identifier assigned to this entity by the operator
        :param keyjar: Key this entity can use to sign things
        :param signer: A dsigner to use for signing documents
            (client registration requests/provide info response) this
            entity produces.
        :param fo_bundle: A bundle of keys that can be used to verify
            the root signature of a compounded metadata statement.
        """

        Operator.__init__(self, iss=iss, keyjar=keyjar, httpcli=srv,
                          jwks_bundle=fo_bundle)

        # Who can sign request from this entity
        self.signer = signer
        self.federation = None

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

    def get_metadata_statement(self, json_ms, cls=MetadataStatement,
                               context=''):
        """
        Unpack and evaluate a compound metadata statement. Goes through the
        necessary three steps.
        * unpack the metadata statement
        * verify that the given statements are expected to be used in this context
        * evaluate the metadata statements (= flatten)

        :param json_ms: The metadata statement as a JSON document or a 
            dictionary
        :param cls: The class the response should be typed into
        :param context: In which context the metadata statement should be used.
        :return: A list of :py:class:`fedoidc.operator.LessOrEqual` instances
        """
        logger.debug('Incoming metadata statement: {}'.format(json_ms))

        _pi = self.unpack_metadata_statement(json_ms=json_ms, cls=cls)
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
        statement['signing_keys'] = self.signing_keys_as_jwks_json()
        return statement

    def update_request(self, req, federation='', loes=None):
        """
        Update a request signed metadata statements.
        
        :param req: The request 
        :param federation: Federation Operator ID
        :param loes: List of :py:class:`fedoidc.operator.LessOrEqual` instances
        :return: The updated request
        """
        if federation:
            if self.signer.signing_service:
                req = self.ace(req, [federation], 'registration')
            else:
                req.update(
                    self.signer.gather_metadata_statements(
                        'registration', fos=[federation]))
        else:
            if loes:
                _fos = list([r.fo for r in loes])
            else:
                return req

            if self.signer.signing_service:
                self.ace(req, _fos, 'registration')
            else:
                req.update(
                    self.signer.gather_metadata_statements(
                        'registration', fos=_fos))
        return req

    def ace(self, req, fos, context):
        """
        Add signing keys, create metadata statement and extend request.
        
        :param req: Request 
        :param fos: List of Federation Operator IDs
        :param context: One of :py:data:`fedoidc.CONTEXTS`
        """
        _cms = MetadataStatement()
        _cms.update(req)
        _cms = self.add_signing_keys(_cms)
        sms = self.signer.create_signed_metadata_statement(_cms, context,
                                                           fos=fos)
        return self.extend_with_ms(req, sms)

    def get_signed_metadata_statements(self, context, fo=None):
        """
        Find a set of signed metadata statements that fulfill the search
        criteria.
        
        :param context: One value out of :py:data:`fedoidc.CONTEXTS` 
        :param fo: A FO ID
        :return: If no *fo* is given a list of FOs. If *fo* a single ID.
            Will raise KeyError if nothin matches.
        """
        if fo is None:
            return self.signer.metadata_statements[context]
        else:
            return self.signer.metadata_statements[context][fo]
