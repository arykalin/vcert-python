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
