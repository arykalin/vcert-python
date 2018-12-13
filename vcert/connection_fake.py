import uuid


def fake_user(email=None):
    fake_user_email = email or "test@example.com"
    fake_user_uuid = str(uuid.uuid4())
    fake_company_uuid = str(uuid.uuid4())
    company_domains = ['auth-demo.com', 'example.com']
    fake_company = 'Example Inc.'
    f = {'user': {'username': fake_user_email, 'id': fake_user_uuid, 'companyId': fake_company_uuid,
                  'firstname': 'John', 'lastname': 'Doe', 'emailAddress': fake_user_email, 'userType': 'EXTERNAL',
                  'userAccountType': 'WEB_UI', 'userStatus': 'ACTIVE', 'roles': ['ADMIN'],
                  'firstLoginDate': '2018-11-27T14:24:37.136+0000', 'creationDate': '2018-11-27T14:24:05.455+0000'},
         'company': {'id': fake_company_uuid, 'name': fake_company, 'companyType': 'TPP_CUSTOMER', 'active': True,
                     'creationDate': '2017-04-16T16:49:51.000+0000', 'domains': company_domains},
         'apiKey': {'userId': fake_user_uuid, 'username': fake_user_email, 'companyId': fake_company_uuid,
                    'apiVersion': 'ALL', 'apiKeyStatus': 'ACTIVE', 'creationDate': '2018-11-27T14:24:05.455+0000',
                    'validityStartDate': '2018-11-27T14:24:05.455+0000',
                    'validityEndDate': '2119-05-26T14:24:05.455+0000'}}
    return f


def fake_zone(zone=None):
    fake_company_uuid = str(uuid.uuid4())
    fake_zone_uuid = str(uuid.uuid4())
    fake_zone = zone or 'default'
    z = {'certificatePolicyIds': {'CERTIFICATE_IDENTITY': ['eaca6114-1569-4903-911e-436404a7cf4d'],
                                  'CERTIFICATE_USE': ['5353c8a7-7b60-486e-9c35-9d2b3ae37038']},
         'companyId': fake_company_uuid,
         'creationDate': '2018-10-11T13:51:56.360+0000',
         'defaultCertificateIdentityPolicyId': 'ef2c3761-74e8-4ec9-8cd4-c9ab1e5c9d94',
         'defaultCertificateUsePolicyId': '17116035-aaae-4c90-a3c6-46e1b0c3c2e7',
         'id': fake_zone_uuid,
         'systemGenerated': False,
         'tag': fake_zone,
         'zoneType': 'OTHER'}
    return z


class ConnectionFake():
    def __init__(self, *args, **kwargs):
        """
        todo: docs
        """

    def ping(self):
        return True

    def auth(self):
        return fake_user()
    
    def register(self, email):
        return fake_user(email)

    def get_zone_by_tag(self, tag):
        return fake_zone(tag)

    def request_cert(self, request, zone):
        raise NotImplementedError

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

