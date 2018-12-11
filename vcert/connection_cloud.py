import requests
import logging as log
from http import HTTPStatus
from .errors import ConnectionError, ServerUnexptedBehavior, ClientBadData

class URLS:
    API_BASE_URL = "https://api.venafi.cloud/v1/"

    USER_ACCOUNTS = "useraccounts"
    PING = "ping"
    ZONES = "zones"
    ZONE_BY_TAG = ZONES + "/tag/%s"
    CERTIFICATE_POLICIES = "certificatepolicies"
    POLICIES_BY_ID = CERTIFICATE_POLICIES + "/%s"
    POLICIES_FOR_ZONE_BY_ID = CERTIFICATE_POLICIES + "?zoneId=%s"
    CERTIFICATE_REQUESTS = "certificaterequests"
    CERTIFICATE_STATUS = CERTIFICATE_REQUESTS + "/%s"
    CERTIFICATE_RETRIEVE = CERTIFICATE_REQUESTS + "/%s/certificate"
    CERTIFICATE_SEARCH = "certificatesearch"
    MANAGED_CERTIFICATES = "managedcertificates"
    MANAGED_CERTIFICATE_BY_ID = MANAGED_CERTIFICATES + "/%s"


TOKEN_HEADER_NAME = "tppl-api-key"

# todo: maybe move this function
def log_errors(data):
    if "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error()


class CloudConnection:
    def __init__(self, token, url=None, *args, **kwargs):
        """
        todo: docs
        """
        self._base_url = url or URLS.API_BASE_URL
        self._token = token

    def _get(self, url, params=None):
        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token})
        return self._process_server_response(r)

    def _post(self, url, params=None, data=None):
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token}, json=data)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self._process_server_response(r)

    @staticmethod
    def _process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            raise ConnectionError("Server status: %s", r.status_code)
        content_type = r.headers.get("content-type")
        if content_type == "text/plain":
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == "application/json":
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, url))
            raise ServerUnexptedBehavior

    def ping(self):
        """
        Check server status
        :return bool:
        """
        status, data = self._get(URLS.PING)

        return status == HTTPStatus.OK and data == "OK"

    def auth(self):
        status, data = self._get(URLS.USER_ACCOUNTS)
        if status == HTTPStatus.OK:
            return data

    def register(self, email):
        status, data = self._post(URLS.USER_ACCOUNTS, data={"username": email, "userAccountType": "API"})
        if status == HTTPStatus.ACCEPTED:
            return data

    def get_zone_by_tag(self, tag):
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        if status == HTTPStatus.OK:
            return data
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)
        else:
            pass

