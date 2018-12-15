#!/usr/bin/env python3
from vcert import TPPConnection
from vcert.common import build_request
from pprint import pprint
from os import environ
import logging

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

    csr = build_request("US", "Moscow", "Moscow", "Venafi", "", "rewrewrwer1.venafi.example.com")
    pprint(conn.make_request_and_wait_certificate(csr, ZONE))

if __name__ == '__main__':
    main()