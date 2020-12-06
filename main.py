import os, socket, multiprocessing, subprocess, getpass

from pexpect import pxssh
from colorama import Fore

def menu():
    os.system('clear')
    print(f'''{Fore.RED}==================={Fore.MAGENTA}======================
{Fore.MAGENTA} _____             {Fore.RED} ____
{Fore.MAGENTA}|__  /___ _ __ ___ {Fore.RED}|  _ \__      ___ __
{Fore.MAGENTA}  / // _ | '__/ _ \{Fore.RED}| |_) \ \ /\ / | '_ \\
{Fore.MAGENTA} / /|  __| | | (_) {Fore.RED}|  __/ \ V  V /| | | |
{Fore.MAGENTA}/____\___|_|  \___/{Fore.RED}|_|     \_/\_/ |_| |_| 

            {Fore.WHITE}Created By HellSec

{Fore.RED}==================={Fore.MAGENTA}======================
                    
                    ''')

def connection(worker, responce):
    main = open(os.devnull, 'w')
    while True:
        ip = worker.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=main)
            responce.put(ip)
        except:
            pass

def getHost():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def map_network(pool_size=255):
    _host = list()

    part = getHost().split('.')
    base_ip = part[0] + '.' + part[1] + '.' + part[2] + '.'

    worker = multiprocessing.Queue()
    responce = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=connection, args=(worker, responce)) for i in range(pool_size)]

    for p in pool:
        p.start()

    for i in range(1, 255):
        worker.put(base_ip + f'{i}')

    for p in pool:
        worker.put(None)

    for p in pool:
        p.join()

    while not responce.empty():
        ip = responce.get()
        _host.append(ip)

    for p in pool:
        p.kill()

    return _host

def portScan(host):
    opened = []
    portLst = [80, 3000, 443, 22, 1337]
    for port in portLst:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((host, port))
            if result == 0:
                opened.append(port)
        except:
            pass

    return opened

def main():
    menu()

    print(f'{Fore.MAGENTA}[!]{Fore.WHITE} Scanning Local Network\n')

    lst = map_network()

    print(f'{Fore.YELLOW}[+]{Fore.WHITE} Found {Fore.MAGENTA}{len(lst)}{Fore.WHITE} Hosts')

    print()
    print(f'{Fore.MAGENTA} PORT {Fore.RED}SCANNER')
    print(f'{Fore.WHITE}='*41 + '\n')

    for host in lst:
        scan = portScan(host)

        if len(scan) != 0:
            print(f'  {Fore.RED}{host} ({len(scan)}){Fore.WHITE} :')
            for port in scan:
                if port == 443:
                    print(f'    Likely a Webserver : {port}')
                if port == 80:
                    print(f'    Likely a Webserver : {port}')
                if port == 3000:
                    print(f'    Beef-XSS Portal    : {port}')
                if port == 22:
                    print(f'    SSH Service        : {port}')
                if port == 1337:
                    print(f'    possible Listener  : {port}')
            print()

main()
