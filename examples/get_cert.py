#!/usr/bin/env python3
from vcert import CloudConnection, CertificateRequest
from pprint import pprint
import string
import random
import logging

logging.basicConfig(level=logging.INFO)
TOKEN = "167edc4b-14c6-4a56-a194-e3270389a662"


def main():
    conn = CloudConnection(TOKEN)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)
    conn.auth()
    conn.read_zone_conf("Default")
    request = CertificateRequest(
                                        common_name=randomword(10) + ".venafi.example.com",
                                        chain_option="first"
                                        )

    pprint(conn.make_request_and_wait_certificate(request, "Default"))

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

if __name__ == '__main__':
    main()
