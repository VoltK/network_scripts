import sys, socket
from datetime import datetime
import argparse
from multiprocessing import Pool
from functools import partial
from subprocess import Popen, PIPE
import re


def check_args():
    parse = argparse.ArgumentParser()

    parse.add_argument('-p', '--port', nargs='*', help='enter ports to scan: -p 21 80 443 8080')
    parse.add_argument('-t', '--target', nargs="*", help='enter your target/targets in format: -t targetsite.com')
    parse.add_argument('-f', '--file', help='enter your file with targets in format: -f file.txt')

    args_list = parse.parse_args()

    return args_list


def get_port(port_list):

    try:
        ports = []

        for p in port_list:
            ports.append(int(p))

    except:
        ports = list(range(1001))

    return ports


def get_target(target):
    try:
        if target:
            print("-" * 100 + f"\nTarget: {target}")
            host = socket.gethostbyname(target)
        else:
            host = socket.gethostbyname(input("Enter your target: "))
    except socket.gaierror:
        print("Wrong address")
        sys.exit()

    return host


def check_port(port, url):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            result = client.connect_ex((url, port))
            if result == 0:
                client.send(b'Scanning you\r\n')
                recv = client.recv(1024).decode()
                res = {port: recv}
                return res

    except KeyboardInterrupt:
        print('Ctrl+C was pressed')
        sys.exit()

    except socket.gaierror:
        print('Some problem with your hostname')
        sys.exit()

    except socket.error:
        print('Cannot connect to server')
        sys.exit()


def get_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", str(s)).groups()[0]
    except:
        mac = ""
    return mac


def main():
    c_args = check_args()

    if c_args.file is not None:
        with open(c_args.file, 'r') as file:
            targets = file.readlines()
    else:
        targets = c_args.target

    for target in targets:
        target = get_target(target.strip())
        ports = get_port(c_args.port)
        mac = get_mac(target)

        print('.' * 100)
        print('Start scanning %s for open ports' % target)
        print('.' * 100)

        start = datetime.now()

        with Pool(50) as pool:
            results = pool.map(partial(check_port, url=target), ports)

            total = 0

            for elem in results:
                if elem != None:
                    total += 1
                    for port, message in elem.items():
                        print(f"[+] Open port: {port}\nReceived message: {message}\n")

        end = datetime.now()

        final_time = end - start

        print(f"Total open ports: {total}")

        if mac != "":
            print(f"MAC ADDRESS: {mac}")

        print("Completed scan in " + str(final_time))


if __name__ == '__main__':
    main()
