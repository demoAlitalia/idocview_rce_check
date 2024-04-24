import re
import requests
import random
import time
#from ResponseCache import RequestCache

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.3",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1",
    "Mozilla/5.0 (Android 7.1.1; SM-G930V Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/54.0.2843.91 Mobile Safari/537.36"
]

def is_http_or_https(url):
    pattern = r'^https?://'
    return bool(re.match(pattern, url))

#主动通信 - 可选用使用代理
def fetch_url_with_proxy(url,proxy_url=None,proxy_auth=None,headers=None):

    default_headers = {
        "User-Agent":get_random_user_agent(),
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language":"zh-CN,zh;q=0.9",
        "Accept-Encoding":"gzip, deflate",
        "Cache-Control":"max-age=0",
        "Proxy-Connection":"keep-alive",
        "Upgrade-Insecure-Requests":'1'
        }
    
    headers = default_headers

    if proxy_url != None:
        with requests.Session() as session:
            
            session.proxies = {
                "http":str(proxy_url),
                "https":str(proxy_url),
            }
            
            if proxy_auth is not None:
                session.auth = proxy_auth
            #HTTPS判断并进行跳过验证
            if is_http_or_https(url) == True:
                response = session.get(url,headers=headers,verify=False)
                time.sleep(1)
            else:
                response = session.get(url,headers=headers)
                time.sleep(1)
        return response
    else:
        if is_http_or_https(url) == True:
            response = requests.get(url,headers=headers,verify=False)
            time.sleep(1)
        else:
            response = requests.get(url,headers=headers)
            time.sleep(1)
        return response

def get_random_user_agent():
    return random.choice(USER_AGENTS)

#版本探测
def detect_server_versioon(text):
    pattern0 = re.compile(r'Version:\s*(\S+)', re.IGNORECASE)
    pattern1 = re.compile(r'\?v=[0-9+.\w]*',re.IGNORECASE)
    flag=None
    
    if pattern0.search(text) == None:
        flag = 2
        match = pattern1.search(text)
        if match == None:
            return False
        return match.group(0),flag
    
    else:
        match = pattern0.search(text)
        key_length = len(match.group(1))
        if key_length > 20:
            flag = 1
            return match.group(1),flag
        if (key_length > 10) and (key_length < 16):
            flag = 0 
            return match.group(1),flag

def detect_main(opp):
    if True:
        if opp == False:
            print("暂时不支持检测Version6及以下的版本")
            return False
        version_number = opp[0]
        print(f"有本漏洞的版本为低于13.10.1_20231115。该站版本为: {version_number}")
    else:
        print("No match found.")

    if opp[1] == 0:
        version_number = version_number.split('.',maxsplit=3)
    elif opp[1] == 1:
        version_number = version_number.split('_',maxsplit=1)
        version_number = version_number[1].split('.',maxsplit=3)
    elif opp[1] == 2:
        version_number = version_number.split('?v=',maxsplit=1)
        version_number = version_number[1].split('.',maxsplit=3)
    
    if int(version_number[0]) > 13:
        print("01-此漏洞不存在")   
    elif int(version_number[0]) < 13:
        print("01-漏洞存在,可一键利用")
    elif int(version_number[0]) == 13:
        if int(version_number[1]) > 10:
            print("02-此漏洞不存在")
        elif int(version_number[1]) == 10:
            if version_number[2] == '1_20231115':
                print("0201-此漏洞不存在")
            elif int(((version_number[2].split('_',maxsplit=1))[0]))>1:
                print("03-此漏洞不存在")
        elif int(version_number[1]) < 10:
            print("02-漏洞存在,可一键利用")


if __name__ == '__main__':
    while True:
        url = input("请输入检测URL:")
        proxy_http = input("请输入您的代理地址(默认为空)：")
        a = fetch_url_with_proxy(url,proxy_http)
        b = detect_server_versioon(a.text)
        detect_main(b)
        print('\n')