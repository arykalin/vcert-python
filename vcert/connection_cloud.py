import requests
import logging as log
from http import HTTPStatus
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr
from .errors import VenafiConnectionError, ServerUnexptedBehavior, ClientBadData
from .common import Zone, CertificateRequest, Certificate, CommonConnection, Policy, ZoneConfig


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


class CloudConnection(CommonConnection):
    def __init__(self, token, url=None, *args, **kwargs):
        """
        todo: docs
        """
        self._base_url = url or URLS.API_BASE_URL
        self._token = token

    def _get(self, url, params=None):
        # todo: catch requests.exceptions
        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token, "Accept": MINE_ANY})
        return self.process_server_response(r)

    def _post(self, url, params=None, data=None):
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token}, json=data)
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

    def _get_cert_status(self, request_id):
        status, data = self._get(URLS.CERTIFICATE_STATUS % request_id)
        if status == HTTPStatus.OK:
            return Certificate.from_server_response(data)

    def _get_policy_by_ids(self, policy_ids):
        policy = Policy()
        for policy_id in policy_ids:
            status, data = self._get(URLS.POLICIES_BY_ID % policy_id)
            if status == HTTPStatus.OK:
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
                    policy.KeyReuse = p.KeyReuse
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

    def request_cert(self, csr, zone):
        z = self.get_zone_by_tag(zone)
        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data={"certificateSigningRequest": csr, "zoneId": z.id})
        if status == HTTPStatus.CREATED:
            request = CertificateRequest.from_server_response(data['certificateRequests'][0])
            return request.id

    def retrieve_cert(self, request):
        raise NotImplementedError

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request):
        raise NotImplementedError

    def read_zone_conf(self, tag):
        z = self.get_zone_by_tag(tag)
        policy = self._get_policy_by_ids((z.default_cert_identity_policy, z.default_cert_use_policy))
        zc = ZoneConfig.from_policy(policy)

    def gen_request(self, zone_config, request):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    def build_request(self, country, province, locality, organization, organization_unit, common_name):
        public_key, private_key = asymmetric.generate_pair('rsa', bit_size=2048)

        data = {
            'country_name': country,
            'state_or_province_name': province,
            'locality_name': locality,
            'organization_name': organization,
            'common_name': common_name,
        }
        if organization_unit:
            data['organizational_unit_name'] = organization_unit
        builder = CSRBuilder(
            data,
            public_key
        )
        builder.hash_algo = "sha256"
        builder.subject_alt_domains = [common_name]
        request = builder.build(private_key)
        return pem_armor_csr(request)