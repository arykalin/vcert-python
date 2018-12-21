import requests
import logging as log
import base64
import re
from http import HTTPStatus
from .errors import ServerUnexptedBehavior, ClientBadData, CertificateRequestError, AuthenticationError, CertificateRenewError
from .common import CommonConnection


class URLS:
    API_BASE_URL = ""

    AUTHORIZE = "authorize/"
    CERTIFICATE_REQUESTS = "certificates/request"
    CERTIFICATE_RETRIEVE = "certificates/retrieve"
    FIND_POLICY = "config/findpolicy"
    CERTIFICATE_REVOKE = "certificates/revoke"
    CERTIFICATE_RENEW = "certificates/renew"
    CERTIFICATE_SEARCH = "certificates/"
    CERTIFICATE_IMPORT = "certificates/import"


TOKEN_HEADER_NAME = "x-venafi-api-key"

# todo: check stdlib
MIME_JSON = "application/json"
MINE_HTML = "text/html"
MINE_TEXT = "text/plain"
MINE_ANY = "*/*"


# todo: maybe move this function
def log_errors(data):
    if "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error(str(e))  # todo: beta formatter


class TPPConnection(CommonConnection):
    def __init__(self, user, password, url, *args, **kwargs):
        """
        todo: docs
        :type str user
        :type str password
        :type str url
        """
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self._token = False
        self._normalize_and_verify_base_url()
        # todo: add timeout check, like self.token = ("token-string-dsfsfdsfdsfdsf", valid_to)

    def _get(self, url="", params=None):
        # todo: catch requests.exceptions
        if not self._token:
            self._token = self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
            MIME_JSON, 'cache-control':
                                                            'no-cache'})
        return self.process_server_response(r)

    def _post(self, url, params=None, data=None):
        if not self._token:
            self._token = self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                MIME_JSON, "cache-control":
                                                                 "no-cache"}, json=data)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _get_cert_status(self, request):
        status, data = self._post(URLS.CERTIFICATE_RETRIEVE % request.id)
        if status == HTTPStatus.OK:
            return data

    def _get_policy_by_ids(self, policy_ids):
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)

    def _normalize_and_verify_base_url(self):
        u = self._base_url
        if u.startswith("http://"):
            u = "https://" + u[7:]
        elif not u.startswith("https://"):
            u = "https://" + u
        if not u.endswith("/"):
            u += "/"
        if not u.endswith("vedsdk/"):
            u += "vedsdk/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d\.]+[a-z\d][:\d]*/vedsdk/$", u):
            raise ClientBadData
        self._base_url = u

    def ping(self):
        status, data = self._get()
        return status == HTTPStatus.OK and "Ready" in data

    def auth(self):
        data = {"Username": self._user, "Password": self._password}

        r = requests.post(self._base_url + URLS.AUTHORIZE, headers={'content-type':
                                                                        MIME_JSON, "cache-control": "no-cache"},
                          json=data)

        status = self.process_server_response(r)
        if status[0] == HTTPStatus.OK:
            return status[1]["APIKey"], status[1]["ValidUntil"]
        else:
            log.error("Authentication status is not %s but %s. Exiting" % (HTTPStatus.OK, status[0]))
            raise AuthenticationError

    # TODO: Need to add service genmerated CSR implementation
    def request_cert(self, request, zone):
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"PolicyDN": self._get_policy_dn(zone),
                                        "PKCS10": request.csr,
                                        "ObjectName": request.friendly_name,
                                        "DisableAutomaticRenewal": "true"})
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return True
        else:
            log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
            raise CertificateRequestError

    def retrieve_cert(self, certificate_request):
        log.debug("Getting certificate status for id %s" % certificate_request.id)

        retrive_request = dict(CertificateDN=certificate_request.id, Format="base64", IncludeChain='true')

        if certificate_request.chain_option == "last":
            retrive_request['RootFirstOrder'] = 'false'
            retrive_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "first":
            retrive_request['RootFirstOrder'] = 'true'
            retrive_request['IncludeChain'] = 'true'
        else:
            retrive_request['IncludeChain'] = 'false'

        status, data = self._post(URLS.CERTIFICATE_RETRIEVE, data=retrive_request)
        if status == HTTPStatus.OK:
            pem64 = data['CertificateData']
            pem = base64.b64decode(pem64)
            # TODO: return private key too
            return pem.decode()
        elif status == HTTPStatus.ACCEPTED:
            log.debug(data['Status'])
            return None
        else:
            log.error("Status is not %s. %s" % HTTPStatus.OK, status)
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, certificate_request_id):
        log.debug("Trying to renew certificate %s" % certificate_request_id)
        status, data = self._post(URLS.CERTIFICATE_RENEW, data={"CertificateDN": certificate_request_id})
        if not data['Success']:
            raise CertificateRenewError
        else:
            return certificate_request_id

    def read_zone_conf(self, tag):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    def _get_policy_dn(self, zone):
        # TODO: add regex here to check if VED\\Policy already in zone.
        # TODO: check and fix number of backslash in zone. Should be \\\\
        return r"\\\\VED\\\\Policy\\\\" + zone
