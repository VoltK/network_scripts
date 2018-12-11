"""
    1) Check if host is UP
    2) If hosts weren't provided -> use default gateway range
    3) Output live hosts to file for further use with NMAP
"""

import nmap
import netifaces
import argparse
import textwrap


def check_args():
    parse = argparse.ArgumentParser(
        prog='alive.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
         \tIf target wasn't provided,
         \tby default alive.py will try to find network gateway and scan it's range: 192.168.1.1/24
         '''))

    parse.add_argument('-o', '--output', help='enter output file name: -o output.txt'
                                              '')
    parse.add_argument('-t', '--target', nargs='*', help='enter your target ip range: -t 192.168.1.1/24 | '
                                                         '    -t 192.168.1.1 192.168.1.55 192.168.1.188')

    args_list = parse.parse_args()

    return args_list


def get_gateway():
    gws = netifaces.gateways()
    # getting router's ip in network
    default_gate = gws['default'][netifaces.AF_INET][0]
    return default_gate


def get_target_range(target):
    # if target wasn't provided -> get default gateway
    if target is None:
        return get_gateway() + "/24"
    else:
        return " ".join(target)


def check_output(output):
    if output is None or not output.endswith('.txt'):
        return 'lives.txt'
    else:
        return output


def who_is_alive(scanner, output):

    total = 0
    with open(output, 'a') as file:
        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                total += 1
                print(f"[+] {host} is {scanner[host].state()}")
                file.write(host + '\n')
    print(f"Total live hosts: {total}")


def main():

    args = check_args()

    target = get_target_range(args.target)

    output = check_output(args.output)

    # creating scanner using nmap class
    nm_scan = nmap.PortScanner()

    print(f"> Start scanning IPs: {target}")

    # scan ip range for live hosts
    nm_scan.scan(hosts=target, arguments=" -sn -PA21,22,25,80,443,989,990,3389")

    who_is_alive(nm_scan, output)

    print(f'Finished. All alive hosts were saved to {output}')


if __name__ == '__main__':
    main()
