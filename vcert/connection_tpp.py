import requests
import logging as log
from http import HTTPStatus
from .errors import ConnectionError, ServerUnexptedBehavior, ClientBadData
from .common import Zone, CertificateRequest, Certificate, CommonConnection

class URLS:
    API_BASE_URL = ""

    AUTHORIZE = "authorize/"
    CERTIFICATE_REQUESTS = "certificates/request"
    CERTIFICATE_RETRIEVE = "certificates/retrieve"
    FIND_POLICY = "config/findpolicy"
    CERTIFICATE_REVOKE = "certificates/revoke"
    CERTIFICATE_REVNEW = "certificates/renew"
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
        log.error(str(e))  #todo: beta formatter


class TPPConnection(CommonConnection):
    def __init__(self, user, password, url, *args, **kwargs):
        """
        todo: docs
        """
        self._base_url = url
        self._user = user
        self._password = password
        self._token = False
        # todo: add timeout check, like self.token = ("token-string-dsfsfdsfdsfdsf", valid_to)



    def _get(self, url="", params=None):
        # todo: catch requests.exceptions
        if not self._token:
            self._token = self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
        MIME_JSON,'cache-control':
                'no-cache'})
        return self.process_server_response(r)

    def _post(self, url, params=None, data=None):
        if not self._token:
            self._token = self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                MIME_JSON,"cache-control":
                "no-cache"}, json=data)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _get_cert_status(self, request_id):
        status, data = self._post(URLS.CERTIFICATE_RETRIEVE % request_id)
        if status == HTTPStatus.OK:
            return data

    def _get_policy_by_ids(self, policy_ids):
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)


    def ping(self):
        status, data = self._get()
        return status == HTTPStatus.OK and "Ready" in data

    def auth(self):
        data = {"Username": self._user, "Password": self._password}

        r = requests.post(self._base_url + URLS.AUTHORIZE, headers={'content-type':
            MIME_JSON, "cache-control": "no-cache"}, json=data)

        status = self.process_server_response(r)
        if status[0] == HTTPStatus.OK:
            return status[1]["APIKey"], status[1]["ValidUntil"]
        else:
            log.error("Authentication status is not %s but %s. Exiting" % (HTTPStatus.OK, status[0]))
            exit(1)

    def register(self):
        return None

    def get_zone_by_tag(self, tag):
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        if status == HTTPStatus.OK:
            return Zone.from_server_response(data)
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)
        else:
            pass

    def request_cert(self, csr, zone):
        """
        :param SigningRequest request:
        :param str zone:
        :return:
        """
        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data={"PKCS10": csr, "PolicyDN": r"\\\\VED\\\\Policy\\\\devops\\\\vcert",
                                                                   "ObjectName":
            "testPythonSDK", "DisableAutomaticRenewal": "true"})
        if status == HTTPStatus.CREATED:
            request = CertificateRequest.from_server_response(data['certificateRequests'][0])
            return request.id
        else:
            log.debug(status)
        # request

    def retrieve_cert(self, request):
        raise NotImplementedError

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request):
        raise NotImplementedError

    def read_zone_conf(self):
        raise NotImplementedError

    def gen_request(self, zone_config, request):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError
