#!/usr/bin/env python3
from vcert import CloudConnection, CertificateRequest, TPPConnection, ConnectionFake
import string
import random
import logging
import time
from os import environ
import unittest

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)

FAKE = environ.get('FAKE')

TOKEN = environ.get('TOKEN')

USER = environ.get('TPPUSER')
PASSWORD = environ.get('TPPPASSWORD')
URL = environ.get('TPPURL')

class TestStringMethods(unittest.TestCase):

    def test_fake(self):
        print("Using fake connection")
        conn = ConnectionFake()
        ZONE = "Default"
        cert_id, pkey=enroll(conn, ZONE)
        # renew(conn, cert_id, pkey)

    def test_cloud(self):
        print("Using cloud connection")
        ZONE = environ['CLOUDZONE']
        conn = CloudConnection(TOKEN)
        cert_id, pkey=enroll(conn, ZONE)
        renew(conn, cert_id, pkey)

    def test_tpp(self):
        ZONE = environ['TPPZONE']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, URL)
        cert_id, pkey=enroll(conn, ZONE)
        renew(conn, cert_id, pkey)

def enroll(conn, ZONE):
    print("Tring to ping url", URL)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    if isinstance(conn, (ConnectionFake or TPPConnection)):
        request = CertificateRequest(
            common_name=randomword(10) + ".venafi.example.com",
            dns_names=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
            email_addresses="e1@venafi.example.com, e2@venafi.example.com",
            ip_addresses=["127.0.0.1", "192.168.1.1"]
        )
    else:
        request = CertificateRequest(
            common_name=randomword(10) + ".venafi.example.com",
        )

    conn.request_cert(request, ZONE)
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)
    print(cert)
    print(request.private_key_pem)
    f = open("/tmp/cert.pem", "w")
    f.write(cert)
    f = open("/tmp/cert.key", "w")
    f.write(request.private_key_pem)
    f.close()
    return request.id, request.private_key_pem

def renew(conn, cert_id, pkey):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        id=cert_id,
    )
    conn.renew_cert(new_request)
    while True:
        new_cert = conn.retrieve_cert(new_request)
        if new_cert:
            break
        else:
            time.sleep(5)
    print(new_cert)
    fn = open("/tmp/new_cert.pem", "w")
    fn.write(new_cert)

def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
