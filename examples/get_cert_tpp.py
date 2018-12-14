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
    # conn.auth()
    # zone = conn.get_zone_by_tag("default")
    # print("zone:", zone)
    # print(build_request("RU", "Moscow", "Moscow", "Venafi", "", "example.com"))

if __name__ == '__main__':
    main()