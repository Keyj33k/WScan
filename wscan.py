#!/usr/bin/env python3

try:
    from socket import socket, AF_INET, SOCK_STREAM, getservbyport
    from requests import get, post
    from bs4 import BeautifulSoup
    from socket import gethostbyaddr, gethostbyname
    from requests.exceptions import MissingSchema, ConnectionError
    from pyfiglet import figlet_format
    from argparse import ArgumentParser, SUPPRESS
    from datetime import datetime
    from socket import gaierror, herror
    from urllib.parse import urlparse
    from sys import exit
    from time import sleep
except ImportError:
    raise RuntimeError(('cannot run wscan because of missing modules. '
                        'Run "pip3 install -r requirements.txt" to fix this issue.'))

"""
wscan - Web Server Scanner
Author: Keyjeek
Date: 03.10.22
Version: 0.0.2
"""

def addr_conv(url_to_conv: str):
    return f"http://{url_to_conv}/"

class WScan:
    def __init__(self, uniformresourcelocator: str, begin_port: int, last_port: int):
        self.last_port = last_port
        self.begin_port = begin_port
        self.uniformresourcelocator = uniformresourcelocator

    def port_check(self):
        if self.begin_port > self.last_port:
            print("port scan canceled: invalid order")
            exit(1)
        elif self.begin_port >= 65534 or self.begin_port <= 0:
            print(f"port check: value {self.begin_port} is invalid")
            exit(1)
        elif self.last_port >= 65535 or self.last_port <= 0:
            print(f"port check: value {self.last_port} is invalid")
            exit(1)
        else:
            return True

    def port_scan(self):
        for port in range(self.begin_port, self.last_port):
            with socket(AF_INET, SOCK_STREAM) as port_scan:
                port_scan.settimeout(5)
                if port_scan.connect_ex((gethostbyname(self.uniformresourcelocator), port)) == 0:

                    try:
                        print(f"TCP, port: {port}, status: open, service: {getservbyport(port)}")
                    except OSError:
                        print(f"TCP, port: {port}, status: open, service: unknown")

    def ipv4_addr(self):
        ipv6 = "".join(gethostbyaddr(self.uniformresourcelocator)[2])
        ipv4 = gethostbyname(self.uniformresourcelocator)
        return f"{ipv4}/{ipv6}"

    def status_code(self):
        return get(addr_conv(self.uniformresourcelocator)).status_code

    def title(self):
        soup = BeautifulSoup(get(addr_conv(self.uniformresourcelocator)).content, "html.parser")
        return soup.title.text

    def links(self):
        soup = BeautifulSoup(get(addr_conv(self.uniformresourcelocator)).content, "html.parser")
        for link in soup.find_all('a'):
            clink = link.get('href')

            try:
                print(f"URL found: {clink} -> status code: {get(clink).status_code}")
            except MissingSchema:
                pass

    def ip_data(self):
        tar_ip = gethostbyname(self.uniformresourcelocator)
        for data in post("http://ip-api.com/batch", json=[{"query": tar_ip}]).json():
            for category, result in data.items():
                print(f"{category}: {result}")

    def http_header(self):
        for category, result in get(addr_conv(self.uniformresourcelocator)).headers.items():
            print(f"{category}: {result}")

    def subdomain_scanner(self, database):
        active_domains = 0
        with open(database, 'r') as file:
            for list_domains in file.read().splitlines():
                uniformresourcelocator = f"http://{list_domains}.{self.uniformresourcelocator}"
                sleep(1.25)

                try:
                    get(uniformresourcelocator)
                    print((f"subdomain found: {uniformresourcelocator} ->" 
                           f" status code: {get(uniformresourcelocator).status_code}"))
                    active_domains += 1
                except (ConnectionError, MissingSchema):
                    pass

        if active_domains == 0:
            print("No subdomains were found, try another wordlist")
            exit(1)


if __name__ == "__main__":
    parser = ArgumentParser(description="WScan - Web Server Scanner")
    parser.add_argument("-v", "--version", action="version",
                        version="wscan - Web Server Scanner, Version 0.0.2", help=SUPPRESS)
    parser.add_argument("-u", "--url", type=str, metavar="target url",
                        help="target url ( format=example.com )", required=True)
    parser.add_argument("-a", "--all", action="store_true", help="complete scan")
    parser.add_argument("-c", "--links", action="store_true", help="collect links + status codes")
    parser.add_argument("-r", "--head", action="store_true", help="server header")
    parser.add_argument("-i", "--ipv4", action="store_true", help="ipv4 informations")
    parser.add_argument("-s", "--sub", action="store_true", help="scan for subdomains")
    parser.add_argument("-w", "--wordl", type=str, metavar="wordlist",
                        help="wordlist for subdomain scanning")
    parser.add_argument("-p", "--pscan", action="store_true", help="port scan")
    parser.add_argument("-f", "--first", type=int, metavar="first port",
                        help="the first port for port scan if enabled")
    parser.add_argument("-l", "--last", type=int, metavar="last port",
                        help="the last port for port scan if enabled")
    args = parser.parse_args()

    def display_help():
        parser.print_help()
        print(("\nexamples:\n"
               "  wscan.py -f 1 -l 100 -a -u example.com\n"
               "  wscan.py -r -u example.com -i\n"
               "  wscan.py -u example.com -p -f 50 -l 100"))
        exit(1)

    if (vars(args)["all"] is True and vars(args)["first"] is None
            or vars(args)["all"] is True and vars(args)["last"] is None):
        display_help()
    elif (vars(args)["pscan"] is True and vars(args)["first"] is None
          or vars(args)["pscan"] is True and vars(args)["last"] is None):
        display_help()
    elif vars(args)["sub"] is True and vars(args)["wordl"] is None:
        print("you forgot to enter a wordlist")
        exit(1)

    try:
        wscan = WScan(args.url, args.first, args.last)
        scan_start = datetime.now()

        print(figlet_format("wscan", font="graffiti"))
        print(figlet_format("Web Server Scanner", font="digital"))
        print("\t" * 4 + "0.0.2")

        if vars(args)["pscan"] is True and wscan.port_check() is False:
            print("\ninvalid port config")
            exit(1)

        print((f"target details\n{'=' * 60}\ntarget: {args.url} ( {''.join(gethostbyaddr(args.url)[0])} )\n"
               f"title: {wscan.title()}\n"
               f"status code: {wscan.status_code()}\n"
               f"addresses: {wscan.ipv4_addr()}\n"))

        if vars(args)["all"] is True:
            print(f"\nhttp response header\n{'=' * 60}")
            wscan.http_header()
            print(f"\nipv4 address data\n{'=' * 60}")
            wscan.ip_data()
            print(f"\navailable links\n{'=' * 60}")
            wscan.links()
            print(f"\nopen ports\n{'=' * 60}")
            wscan.port_scan()
        if vars(args)["head"] is True:
            print(f"\nhttp response header\n{'=' * 60}")
            wscan.http_header()
        if vars(args)["ipv4"] is True:
            print(f"\nipv4 address data\n{'=' * 60}")
            wscan.ip_data()
        if vars(args)["links"] is True:
            print(f"\navailable links\n{'=' * 60}")
            wscan.links()
        if vars(args)["pscan"] is True:
            print(f"\nopen ports\n{'=' * 60}")
            wscan.port_scan()
        if vars(args)["sub"] is True:
            print(f"\nactive subdomains\n{'=' * 60}")
            wscan.subdomain_scanner("subdomains.txt") if args.wordl == "default" else wscan.subdomain_scanner(args.wordl)

        print((f"\n\nwscan done\n{'=' * 60}\n"
               f"scanned {args.url} in {datetime.now() - scan_start}"))
    except KeyboardInterrupt:
        print("\nwscan exits due interruption")
    except gaierror:
        print("\ninvalid url, use a format like this: example.com")
    except (ConnectionError, herror):
        print(f"\ncannot scan {args.url}")
    except FileNotFoundError:
        print(f"subdomain scanning failed: wordlist is missing")
