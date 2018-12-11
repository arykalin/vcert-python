#!/usr/bin/env python3
from vcert import CloudConnection
from pprint import pprint

TOKEN = ""


def main():
    conn = CloudConnection(TOKEN)
    status = conn.ping()
    print("Server online:", status)
    if status:
        pass
    conn.auth()
    pprint(conn.get_zone_by_tag("default"))


if __name__ == '__main__':
    main()