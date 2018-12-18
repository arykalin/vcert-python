import requests
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr
import logging as log
from http import HTTPStatus
from .errors import VenafiConnectionError, VenafiServerUnexptedBehavior, VenafiClientBadData, VenafiCertificateRequestError, VenafiAuthenticationError
from .common import Zone, CertificateRequest, Certificate, CommonConnection, CertStatuses, CertRequest

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
        log.error(str(e))  # todo: beta formatter


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
                                                                        MIME_JSON, "cache-control": "no-cache"},
                          json=data)

        status = self.process_server_response(r)
        if status[0] == HTTPStatus.OK:
            return status[1]["APIKey"], status[1]["ValidUntil"]
        else:
            log.error("Authentication status is not %s but %s. Exiting" % (HTTPStatus.OK, status[0]))
            raise VenafiAuthenticationError

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
        csr = builder.build(private_key)
        csr = pem_armor_csr(csr)
        # request = dict(friendly_name=common_name,csr=csr)
        request = CertRequest(csr=csr, friendly_name=common_name)
        return request

    def request_cert(self, request, zone):
        """
        :param SigningRequest request:
        :param str zone:
        :return:
        """
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"PKCS10": request.__dict__['csr'], "PolicyDN":
                                      r"\\\\VED\\\\Policy\\\\devops\\\\vcert",
                                        "ObjectName": request.__dict__['friendly_name'],
                                        "DisableAutomaticRenewal": "true"})
        if status == HTTPStatus.OK:
            request = CertificateRequest.from_tpp_server_response(data)
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return request.id
        else:
            log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
            raise VenafiCertificateRequestError

    def retrieve_cert(self, request_id):
        log.debug("Getting certificate status for id %s" % request_id)
        status, data = self._post(URLS.CERTIFICATE_RETRIEVE, data={
            'CertificateDN': request_id,
            'Format': "base64",
            'RootFirstOrder': 'true',
            'IncludeChain': 'true',
        })
        if status == HTTPStatus.OK:
            return data
        elif status == HTTPStatus.ACCEPTED:
            log.debug(data['Status'])
            return None
        else:
            log.error("Status is not %s. %s" % HTTPStatus.OK, status)
            raise VenafiServerUnexptedBehavior

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
