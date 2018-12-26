from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, with_statement
import requests
import logging as log
from .http import HTTPStatus
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError)
from .common import Zone, CertificateRequest, CommonConnection, Policy, ZoneConfig


class CertStatuses:
    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'
    FAILED = 'FAILED'
    ISSUED = 'ISSUED'


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


class CondorChainOptions:
    ROOT_FIRST = "ROOT_FIRST"
    ROOT_LAST = "EE_FIRST"


TOKEN_HEADER_NAME = "tppl-api-key"

# todo: check stdlib
MIME_JSON = "application/json"
MINE_TEXT = "text/plain"
MINE_ANY = "*/*"


class CertificateStatusResponse:
    def __init__(self, d):
        self.status = d['status']
        self.subject = d['subjectDN']
        self.zoneId = d['zoneId']
        self.manage_id = d.get('managedCertificateId')


# todo: maybe move this function
def log_errors(data):
    if "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error(str(e))  # todo: beta formatter


class CloudConnection(CommonConnection):
    def __init__(self, token, url=None):
        """
        todo: docs
        """
        self._base_url = url or URLS.API_BASE_URL
        self._token = token

    def _get(self, url, params=None):
        # todo: catch requests.exceptions
        r = requests.get(self._base_url + url, params=params,
                         headers={TOKEN_HEADER_NAME: self._token, "Accept": MINE_ANY, "cache-control": "no-cache"})
        return self.process_server_response(r)

    def _post(self, url, data=None):
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, json=data,
                              headers={TOKEN_HEADER_NAME: self._token,  "cache-control": "no-cache"}, )
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    @staticmethod
    def _process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            raise VenafiConnectionError("Server status: %s, %s", (r.status_code, r.request.url))
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

    def _get_cert_status(self, request):
        status, data = self._get(URLS.CERTIFICATE_STATUS % request.id)
        if status == HTTPStatus.OK:
            request_status = CertificateStatusResponse(data)
            return request_status
        else:
            raise ServerUnexptedBehavior

    def _get_policy_by_ids(self, policy_ids):
        policy = Policy()
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)
            if status != HTTPStatus.OK:
                log.error("")  # todo: log
                continue
            p = Policy.from_server_response(data)
            if p.policy_type == p.Type.CERTIFICATE_IDENTITY:  # todo: replace with somethin more pythonic
                policy.SubjectCNRegexes = p.SubjectCNRegexes
                policy.SubjectORegexes = p.SubjectORegexes
                policy.SubjectOURegexes = p.SubjectOURegexes
                policy.SubjectSTRegexes = p.SubjectSTRegexes
                policy.SubjectLRegexes = p.SubjectLRegexes
                policy.SubjectCRegexes = p.SubjectCRegexes
                policy.SANRegexes = p.SANRegexes
            elif p.policy_type == p.Type.CERTIFICATE_USE:
                policy.key_types = p.key_types[:]
                policy.key_reuse = p.key_reuse
        return policy

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
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        if status == HTTPStatus.OK:
            return Zone.from_server_response(data)
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)
        else:
            pass

    def request_cert(self, request, zone):
        z = self.get_zone_by_tag(zone)
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"certificateSigningRequest": request.csr, "zoneId": z.id})
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            return True
        else:
            log.error("unexpected server response %s: %s", status, data)
            raise CertificateRequestError

    def retrieve_cert(self, request):
        url = URLS.CERTIFICATE_RETRIEVE % request.id
        if request.chain_option == "first":
            url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_FIRST
        elif request.chain_option == "last":
            url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_LAST
        else:  # todo: maybe over values
            log.error("chain option %s is not valid" % request.chain_option)
            raise ClientBadData
        # todo: make search by thumbprint
        status, data = self._get(URLS.CERTIFICATE_STATUS % request.id)
        # TODO: run it in loop
        if status == HTTPStatus.OK or HTTPStatus.CONFLICT:
            if data['status'] == CertStatuses.PENDING or data['status'] == CertStatuses.REQUESTED:
                log.info("Certificate status is %s." % data['status'])
                return None
            elif data['status'] == CertStatuses.FAILED:
                log.debug("Status is %s. Returning data for debug" % data['status'])
                return "Certificate FAILED"
            elif data['status'] == CertStatuses.ISSUED:
                status, data = self._get(url)
                if status == HTTPStatus.OK:
                    return data
                else:
                    raise ServerUnexptedBehavior
            else:
                raise ServerUnexptedBehavior
        else:
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        # not supported in cloud
        raise NotImplementedError

    def renew_cert(self, request):
        zone = None
        manage_id = None
        if not request.id and not request.thumbprint:
            log.error("prev_cert_id or thumbprint or manage_id must be specified for renewing certificate")
            raise ClientBadData
        if request.thumbprint:
            r = self.search_by_thumbprint(request.thumbprint)
            request.id = r.id
        if request.id:
            prev_request = self._get_cert_status(CertificateRequest(id=request.id))
            manage_id = prev_request.manage_id
            # todo: fill request object fields
            zone = prev_request.zoneId
        if not manage_id:
            log.error("Can`t find manage_id")
            raise ClientBadData
        status, data = self._get(URLS.MANAGED_CERTIFICATE_BY_ID % manage_id)
        if status == HTTPStatus.OK:
            request.id = data['latestCertificateRequestId']
        else:
            raise ServerUnexptedBehavior
        if not zone:
            prev_request = self._get_cert_status(CertificateRequest(id=request.id))
            zone = prev_request.zoneId
        d = {"existingManagedCertificateId": manage_id, "zoneId": zone}
        if request.csr:
            d["certificateSigningRequest"] = request.csr
            d["reuseCSR"] = False
        else:
            d["reuseCSR"] = True

        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data=d)
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            return True
        else:
            log.error("server unexpected status %s" % status)
            raise CertificateRenewError

    def search_by_thumbprint(self, request):
        raise NotImplementedError

    def read_zone_conf(self, tag):
        z = self.get_zone_by_tag(tag)
        policy = self._get_policy_by_ids((z.default_cert_identity_policy, z.default_cert_use_policy))
        zc = ZoneConfig.from_policy(policy)
        return zc

    def import_cert(self, request):
        # not supported in cloud
        raise NotImplementedError