#!/usr/bin/env python3
from vcert import CloudConnection
from vcert.common import build_request
from pprint import pprint
import logging

logging.basicConfig(level=logging.INFO)
TOKEN = ""


def main():
    conn = CloudConnection(TOKEN)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)
    conn.auth()

    csr = build_request("US", "Moscow", "Moscow", "Venafi", "", "rewrewrwer1.venafi.example.com")
    pprint(conn.make_request_and_wait_certificate(csr, "Default"))


if __name__ == '__main__':
    main()
