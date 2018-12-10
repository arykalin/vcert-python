import requests
from .errors import ConnectionError

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


class CloudConnection:
    def __init__(self, token, url=None, *args, **kwargs):
        """
        todo: docs
        """
        self._base_url = url or URLS.API_BASE_URL

    def _get(self, url, params=None):
        r = requests.get(self._base_url + url)
        if r.status_code != 200:
            raise ConnectionError("Server status: %s", r.status_code)
        return r.content

    def ping(self):
        """
        Check server status
        :return bool:
        """
        r = self._get(URLS.PING)
        if r:
            return True
        return False
