#!/usr/bin/env python3
from vcert import CloudConnection
from vcert.common import build_request
from pprint import pprint

TOKEN = ""


def main():
    conn = CloudConnection(TOKEN)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)
    conn.auth()
    zone = conn.get_zone_by_tag("default")
    print("zone:", zone)
    print(build_request("RU", "Moscow", "Moscow", "Venafi", "", "example.com"))

if __name__ == '__main__':
    main()