#!/usr/bin/env python3
import time
from vcert import TPPConnection, CertificateRequest
from pprint import pprint
from os import environ
import logging
import random, string

logging.basicConfig(level=logging.DEBUG)

USER = (environ['TPPUSER'])
PASSWORD = (environ['TPPPASSWORD'])
URL = (environ['TPPURL'])
ZONE = (environ['TPPZONE'])


def main():
    print("Tring to ping url", URL)
    conn = TPPConnection(USER, PASSWORD, URL)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    request = CertificateRequest(
        common_name=randomword(10) + ".venafi.example.com",
        chain_option="first",
        dns_names=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
        email_addresses="e1@venafi.example.com, e2@venafi.example.com",
        ip_addresses=["127.0.0.1", "192.168.1.1"]
    )

    request = conn.request_cert(request, ZONE)
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)
    print(cert)
    print(request.private_key)
    f = open("/tmp/cert.pem","w")
    f.write(cert)
    f = open("/tmp/cert.key","w")
    f.write(request.private_key)

    renew_id=request.id
    conn.renew_cert(renew_id)
    new_request = CertificateRequest(
        id=renew_id,
        chain_option="first",
    )
    while True:
        new_cert = conn.retrieve_cert(new_request)
        if new_cert:
            break
        else:
            time.sleep(5)
    print(new_cert)
    f = open("/tmp/new_cert.pem","w")
    f.write(new_cert)


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
