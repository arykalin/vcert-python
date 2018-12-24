#!/usr/bin/env python3
from vcert import CloudConnection, CertificateRequest, TPPConnection, ConnectionFake
import string
import random
import logging
import time
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    FAKE = environ.get('FAKE')

    TOKEN = environ.get('TOKEN')

    USER = environ.get('TPPUSER')
    PASSWORD = environ.get('TPPPASSWORD')
    URL = environ.get('TPPURL')

    if FAKE == "true":
        print("Using fake connection")
        conn = ConnectionFake()
        ZONE = "Default"
    elif TOKEN:
        print("Using cloud connection")
        ZONE = environ['CLOUDZONE']
        conn = CloudConnection(TOKEN)
    elif USER and PASSWORD and URL:
        ZONE = environ['TPPZONE']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, URL)
    else:
        raise Exception("require environment vaiable TOKEN or USER,PASSWORD,URL")

    print("Tring to ping url", URL)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    if USER or FAKE == 'true':
        request = CertificateRequest(
            common_name=randomword(10) + ".venafi.example.com",
            chain_option="first",
            dns_names=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
            email_addresses="e1@venafi.example.com, e2@venafi.example.com",
            ip_addresses=["127.0.0.1", "192.168.1.1"]
        )
    else:
        request = CertificateRequest(
            common_name=randomword(10) + ".venafi.example.com",
            chain_option="first",
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

    if USER:
        print("Trying to renew certificate")
        renew_id = request.id
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
        fn = open("/tmp/new_cert.pem", "w")
        fn.write(new_cert)

def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
