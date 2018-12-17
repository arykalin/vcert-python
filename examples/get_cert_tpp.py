#!/usr/bin/env python3
import time
from vcert import TPPConnection
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
    print("Tring to ping url",URL)
    conn = TPPConnection(USER,PASSWORD,URL)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    req = {

    }
    request = conn.build_request("US", "Moscow", "Moscow", "Venafi", "", randomword(10)+".venafi.example.com")
    request_id = conn.request_cert(request, ZONE)
    while True:
        cert = conn.retrieve_cert(request_id)
        if cert == 'Pending':
            time.sleep(5)
        else:
            break
    pprint(cert)
    # pprint(conn.make_request_and_wait_certificate(request, ZONE))

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

if __name__ == '__main__':
    main()