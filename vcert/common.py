import datetime
import dateutil.parser
import time
import logging as log
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr
from pprint import pprint
from http import HTTPStatus
from .errors import VenafiConnectionError, ServerUnexptedBehavior, BadData

MIME_JSON = "application/json"
MINE_HTML = "text/html"
MINE_TEXT = "text/plain"
MINE_ANY = "*/*"

class CertStatuses:
    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'


class CertField(str):
    def __init__(self, *args, **kwargs):
        self.locked = False
        super(CertField, self).__init__(*args, **kwargs)


class Zone:
    def __init__(self, id, company_id, tag, zonetype, cert_policy_ids, default_cert_identity_policy,
                 default_cert_use_policy, system_generated, creation_date):
        """
        :param str id:
        :param str company_id:
        :param str tag:
        :param str zonetype:
        :param cert_policy_ids:
        :param str default_cert_identity_policy:
        :param str default_cert_use_policy:
        :param bool system_generated:
        :param datetime.datetime creation_date:
        """
        self.id = id
        self.company_id = company_id
        self.tag = tag
        self.zonetype = zonetype
        self.cert_policy_ids = cert_policy_ids
        self.default_cert_identity_policy = default_cert_identity_policy
        self.default_cert_use_policy = default_cert_use_policy
        self.system_generated = system_generated
        self.creation_date = creation_date

    def __repr__(self):
        return "%s (%s)" % (self.tag, self.id)

    def __str__(self):
        return self.tag

    @classmethod
    def from_server_response(cls, d):
        return cls(d['id'], d['companyId'], d['tag'], d['zoneType'], d['certificatePolicyIds'],
                   d['defaultCertificateIdentityPolicyId'], d['defaultCertificateUsePolicyId'], d['systemGenerated'],
                   dateutil.parser.parse(d['creationDate']))


class KeyTypes:
    RSA = "rsa"
    ECDSA = "ecdsa"


class KeyType:
    def __init__(self, key_type, key_sizes=None, key_curves=None):
        self.key_type = key_type.lower()
        if self.key_type == KeyTypes.RSA:
            self.key_size = key_sizes
        elif self.key_type == KeyTypes.ECDSA:
            self.key_curves = list([x.lower() for x in key_curves])
        else:
            log.error("unknown key type: %s" % key_type)
            raise BadData

    def __repr__(self):
        return "KeyType(%s, %s)" % (self.key_type, self.key_size or self.key_curves)


class ZoneConfig:
    def __init__(self, organization=None, organizational_unit=None, country=None, province=None, locality=None,
                 CustomAttributeValues=None, SubjectCNRegexes=None, SubjectORegexes=None, SubjectOURegexes=None,
                 SubjectSTRegexes=None, SubjectLRegexes=None, SubjectCRegexes=None, SANRegexes=None,
                 allowed_key_configurations=None, KeySizeLocked=None, HashAlgorithm=None):
        """
        :param CertField organization:
        :param list[str] organizational_unit:
        :param CertField country:
        :param CertField province:
        :param CertField locality:
        :param dict[str, str] CustomAttributeValues:
        :param list[str] SubjectCNRegexes:
        :param list[str] SubjectORegexes:
        :param list[str] SubjectOURegexes:
        :param list[str] SubjectSTRegexes:
        :param list[str] SubjectLRegexes:
        :param list[str] SubjectCRegexes:
        :param list[str] SANRegexes:
        :param list[KeyType] allowed_key_configurations:
        :param bool KeySizeLocked:
        :param HashAlgorithm:
        """

        self.allowed_key_configurations = allowed_key_configurations or []

    @classmethod
    def from_policy(cls, policy):
        """
        :param Policy policy:
        """
        zone_config = cls()
        zone_config.allowed_key_configurations = policy.key_types[:]
        return zone_config


class Policy:
    class Type:
        CERTIFICATE_IDENTITY = "CERTIFICATE_IDENTITY"
        CERTIFICATE_USE = "CERTIFICATE_USE"

    def __init__(self, policy_type=None, id=None, company_id=None, name=None, system_generated=None, creation_date=None,
                 cert_provider_id=None,
                 SubjectCNRegexes=None, SubjectORegexes=None, SubjectOURegexes=None, SubjectSTRegexes=None,
                 SubjectLRegexes=None,
                 SubjectCRegexes=None, SANRegexes=None, key_types=None, KeyReuse=None):
        """
        :param str policy_type:
        :param str id:
        :param str company_id:
        :param str name:
        :param bool ystem_generated:
        :param datetime.datetime creation_date:
        :param str cert_provider_id:
        :param list[str] SubjectCNRegexes:
        :param list[str] SubjectORegexes:
        :param list[str] SubjectOURegexes:
        :param list[str] SubjectSTRegexes:
        :param list[str] SubjectLRegexes:
        :param list[str] SubjectCRegexes:
        :param list[str] SANRegexes:
        :param list[KeyType] key_types:
        :param bool KeyReuse:
        """
        self.policy_type = policy_type
        self.id = id
        self.company_id = company_id
        self.name = name
        self.system_generated = system_generated
        self.creation_date = creation_date
        self.cert_provider_id = cert_provider_id
        self.SubjectCNRegexes = SubjectCNRegexes
        self.SubjectORegexes = SubjectORegexes
        self.SubjectOURegexes = SubjectOURegexes
        self.SubjectSTRegexes = SubjectSTRegexes
        self.SubjectLRegexes = SubjectLRegexes
        self.SubjectCRegexes = SubjectCRegexes
        self.SANRegexes = SANRegexes
        self.key_types = key_types
        self.KeyReuse = KeyReuse

    @classmethod
    def from_server_response(cls, d):
        policy = cls(d['certificatePolicyType'], d['id'], d['companyId'], d['name'], d['systemGenerated'],
                     dateutil.parser.parse(d['creationDate']), d.get('certificateProviderId'),
                     d.get('subjectCNRegexes', []), d.get('subjectORegexes', []), d.get('subjectOURegexes', []),
                     d.get('subjectSTRegexes', []), d.get('subjectLRegexes', []), d.get('subjectCRegexes', []),
                     d.get('sanRegexes', []), [], d.get('keyReuse'))
        for kt in d.get('keyTypes', []):
            policy.key_types.append(KeyType(key_type=kt['keyType'], key_sizes=kt['keyLengths']))  # todo: curves
        return policy

    def __repr__(self):
        return "policy [%s] %s (%s)" % (self.policy_type, self.name, self.id)


class CertificateRequest:
    def __init__(self, id=None,
                 status=None,
                 subject=None,
                 dns_names=None,
                 email_addresses=None,
                 ip_addresses=None,
                 attributes=None,
                 signature_algorithm=None,
                 public_key_algorithm=None,
                 key_type=None,
                 key_length=None,
                 key_curve=None,
                 private_key=None,
                 csr_origin=None,
                 key_password=None,
                 csr=None,
                 friendly_name=None,
                 chain_option=None,
                 country=None,
                 province=None,
                 locality=None,
                 organization=None,
                 organization_unit=None,
                 common_name=None):

        self.csr = csr
        self.friendly_name = friendly_name
        self.chain_option = chain_option
        self.subject = subject
        self.dns_names = dns_names
        self.email_addresses = email_addresses
        self.ip_addresses = ip_addresses
        self.attributes = attributes
        self.signature_algorithm = signature_algorithm
        self.public_key_algorithm = public_key_algorithm
        self.key_type = key_type
        self.key_length = key_length
        self.key_curve = key_curve
        self.private_key = private_key
        self.csr_origin = csr_origin
        self.key_password = key_password
        self.csr = csr
        self.friendly_name = friendly_name
        self.chain_option = chain_option
        self.id = id
        self.status = status
        self.country = country
        self.province = province
        self.locality = locality
        self.organization = organization
        self.organization_unit = organization_unit
        self.common_name = common_name

    @classmethod
    def from_server_response(cls, d):
        return cls(d['id'], d['status'])

    @classmethod
    def from_tpp_server_response(cls, d):
        return cls(d['CertificateDN'], d['Guid'])

    def build_request(self):
        public_key, private_key = asymmetric.generate_pair('rsa', bit_size=2048)

        data = {
            'country_name': self.country,
            'state_or_province_name': self.province,
            'locality_name': self.locality,
            'organization_name': self.organization,
            'common_name': self.common_name,
        }
        if self.organization_unit:
            data['organizational_unit_name'] = self.organization_unit
        builder = CSRBuilder(
            data,
            public_key
        )
        builder.hash_algo = "sha256"
        builder.subject_alt_domains = [self.common_name]
        csr = builder.build(private_key)
        csr = pem_armor_csr(csr)
        # request = dict(friendly_name=common_name,csr=csr)
        # request =
        return CertificateRequest(csr=csr, friendly_name=self.common_name)


class Certificate:
    def __init__(self, id, status):
        self.id = id
        self.status = status

    @classmethod
    def from_server_response(cls, d):
        return cls(d['id'], d['status'])


class CommonConnection:
    def _get_cert_status(self, request_id):
        raise NotImplementedError

    def _get_policy_by_ids(self, policy_ids):
        raise NotImplementedError

    def ping(self):
        raise NotImplementedError

    def auth(self):
        raise NotImplementedError

    def register(self, email):
        raise NotImplementedError

    def get_zone_by_tag(self, tag):
        """
        :param str tag:
        :rtype Zone
        """
        raise NotImplementedError

    def build_request(self, country, province, locality, organization, organization_unit, common_name):
        """
        :param str csr: Certitficate in PEM format
        :param str zone: Venafi zone tag name
        """
        raise NotImplementedError

    def request_cert(self, csr, zone):
        """
        :param str csr: Certitficate in PEM format
        :param str zone: Venafi zone tag name
        """
        raise NotImplementedError

    def retrieve_cert(self, request_id):
        raise NotImplementedError

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request):
        raise NotImplementedError

    def read_zone_conf(self, tag):
        """
        :param str tag:
        :rtype ZoneConfig
        """
        raise NotImplementedError

    def gen_request(self, zone_config, request):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    def make_request_and_wait_certificate(self, csr, zone):
        """
        :param str csr:
        :param str zone:
        """
        pickup_id = self.request_cert(csr, zone)
        log.info("Send certificate request, got pickupId: %s" % pickup_id)
        while True:
            time.sleep(10)
            log.info("Checking status for %s" % pickup_id)
            cert = self._get_cert_status(pickup_id)
            if cert.status not in (CertStatuses.REQUESTED, CertStatuses.PENDING):
                break
        log.info("Status: %s" % cert.status)
        return cert

    @staticmethod
    def process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            raise VenafiConnectionError("Server status: %s, %s\n Response: %s",
                                        (r.status_code, r.request.url, r._content))
        content_type = r.headers.get("content-type")
        if content_type == MINE_TEXT:
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == MINE_HTML:
            log.debug(r.text)
            return r.status_code, r.text
        # content-type in respons is  application/json; charset=utf-8
        elif content_type.startswith(MIME_JSON):
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior
