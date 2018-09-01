import sys, socket
from datetime import datetime
import argparse
from multiprocessing import Pool
from functools import partial


def check_args():
    parse = argparse.ArgumentParser()

    parse.add_argument('-p', '--port', nargs='*', help='enter ports to scan: -p 21 80 443 8080')
    parse.add_argument('-t', '--target', help='enter your target in format: -t targetsite.com')

    args_list = parse.parse_args()

    return args_list


def get_port(port_list):
    ports = []
    if len(port_list) > 0:
        for p in port_list:
            ports.append(int(p))
    else:
        ports = list(range(1001))
    return ports


def get_url(target):
    try:
        if target:
            print(target + ' is ' + socket.gethostbyname(target))
            url = socket.gethostbyname(target)
        else:
            url = socket.gethostbyname(input("Enter your target: "))
    except socket.gaierror:
        print("Wrong address")
        sys.exit()

    return url


def check_port(port, url):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = client.connect_ex((url, port))
        if result == 0:
            print("%d port is open" % port)
        else:
            print('%d port is closed' % port)
        client.close()

    except KeyboardInterrupt:
        print('Ctrl+C was pressed')
        sys.exit()

    except socket.gaierror:
        print('Some problem with your hostname')
        sys.exit()

    except socket.error:
        print('Cannot connect to server')
        sys.exit()


def main():
    c_args = check_args()

    url = get_url(c_args.target)
    ports = get_port(c_args.port)

    print('.' * 100)
    print('Start scanning %s for open ports' % url)
    print('.' * 100)

    start = datetime.now()

    with Pool(50) as pool:
        pool.map(partial(check_port, url=url), ports)

    end = datetime.now()

    final_time = end - start

    print("Completed scan in " + str(final_time))


if __name__ == '__main__':
    main()
