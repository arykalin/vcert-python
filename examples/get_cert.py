#!/usr/bin/env python3
from vcert import CloudConnection


TOKEN = ""


def main():
    conn = CloudConnection(TOKEN)
    status = conn.ping()
    print("Server online:", status)
    if status:
        pass


if __name__ == '__main__':
    main()