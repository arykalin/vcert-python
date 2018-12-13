import time
import requests
import logging as log
from http import HTTPStatus
from .errors import ConnectionError, ServerUnexptedBehavior, ClientBadData
from .common import Zone, CertificateRequest, Certificate


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


class CertStatuses:
    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'

TOKEN_HEADER_NAME = "tppl-api-key"

# todo: check stdlib
MIME_JSON = "application/json"
MINE_TEXT = "text/plain"
MINE_ANY = "*/*"


# todo: maybe move this function
def log_errors(data):
    if "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error(str(e))  #todo: beta formatter


class CloudConnection:
    def __init__(self, token, url=None, *args, **kwargs):
        """
        todo: docs
        """
        self._base_url = url or URLS.API_BASE_URL
        self._token = token

    def _get(self, url, params=None):
        # todo: catch requests.exceptions
        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token, "Accept": MINE_ANY})
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
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            raise ConnectionError("Server status: %s, %s", (r.status_code, r.request.url))
        content_type = r.headers.get("content-type")
        if content_type == MINE_TEXT:
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == MIME_JSON:
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior

    def _get_cert_status(self, request_id):
        status, data = self._get(URLS.CERTIFICATE_STATUS % request_id)
        if status == HTTPStatus.OK:
            return Certificate.from_server_response(data)

    def _get_policy_by_ids(self, policy_ids):
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)

    def ping(self):
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
        """
        :param str tag:
        """
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        if status == HTTPStatus.OK:
            return Zone.from_server_response(data)
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)
        else:
            pass

    def request_cert(self, csr, zone):
        """
        :param str csr:
        :param str zone:
        """
        z = self.get_zone_by_tag(zone)
        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data={"certificateSigningRequest": csr, "zoneId": z.id})
        if status == HTTPStatus.CREATED:
            request = CertificateRequest.from_server_response(data['certificateRequests'][0])
            pickup_id = request.id
            log.info("Send certificate request, got pickupId: %s" % pickup_id)
            while True:
                time.sleep(10)
                log.info("Checking status for %s" % pickup_id)
                cert = self._get_cert_status(pickup_id)
                if cert.status not in (CertStatuses.REQUESTED, CertStatuses.PENDING):
                    break
            log.info("Status: %s" % cert.status)
            return cert

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
