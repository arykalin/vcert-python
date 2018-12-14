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
        # todo: add timeout check, like self.token = ("token-string-dsfsfdsfdsfdsf", valid_to)



    def _get(self, url="", params=None):
        # todo: catch requests.exceptions
        if not self._token:
            self._token = self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
        MIME_JSON,'cache-control':
                'no-cache'})
        return self._process_server_response(r)

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
        return self._process_server_response(r)

    @staticmethod
    def _process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            raise ConnectionError("Server status: %s, %s", (r.status_code, r.request.url))
        content_type = r.headers.get("content-type")
        if content_type == MINE_HTML:
            log.debug(r.text)
            return r.status_code, r.text
        # content-type in respons is  application/json; charset=utf-8
        elif MIME_JSON in content_type:
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior

    def _get_cert_status(self, request_id):
        status, data = self._get(URLS.CERTIFICATE_STATUS % request_id)
        if status == HTTPStatus.OK:
            return data

    def _get_policy_by_ids(self, policy_ids):
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)


    def ping(self):
        status, data = self._get()
        return status == HTTPStatus.OK and "Ready" in data

    def auth(self):
        status, data = self._post(URLS.AUTHORIZE, data={"Username": self._user, "Password": self._password})
        if status == HTTPStatus.OK:
            return data["APIKey"], data["ValidUntil"]

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

    def request_cert(self, request, zone):
        """
        :param SigningRequest request:
        :param str zone:
        :return:
        """
        request

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
