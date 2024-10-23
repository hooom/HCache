import json, time
import os
import pika
import threading
import traceback
import requests, aiohttp
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import random, socket, asyncio
from concurrent.futures import ProcessPoolExecutor
#import http.client
from concurrent.futures import as_completed
import multiprocessing
#http.client.HTTPConnection._http_vsn = 10
#http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'



requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "iframe", "Accept-Encoding": "gzip, deflate",
    "Sec-Fetch-Mode": "navigate",
    "sec-ch-ua": "\"Google Chrome\";v=\"95\", \"Chromium\";v=\"95\", \";Not A Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "sec-ch-ua-platform": "\"macOS\"",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}


def add_header(request, key, value):
    new_header = request[:-2] + key + ': ' + value + '\r\n\r\n'
    return new_header

def get_ip_address(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

async def wcpdetection(scan_ts, url, round, domain, rank, func, ch, aheaders = {}, param = {}):

    buster1 = str(random.randint(1 ,1000000))
    p = {'wpctest' :buster1}
    p.update(param)


    p1 = {'wcptest' :str(random.randint(1 ,1000000))}
    p1.update(param)
    attack_headers = {**headers, **aheaders}


    s = requests.session()

    try:
        normal_response = s.get(url = url, headers=headers, params=p, verify=False, timeout=25)
        if normal_response.status_code >= 400:
            s.close()
            return
        ip_address = get_ip_address(url.split("://")[1].split("/")[0])
        attack_response = s.get(url = url, headers=attack_headers, params=p1, verify=False, timeout=25)
        if normal_response.status_code != attack_response.status_code:
            verify_response = s.get(url = url, headers = headers, params=p1 ,verify=False, timeout=25)
            if attack_response.status_code == verify_response.status_code:
                data = {'url': url, 'payload': aheaders, 'response': attack_response.status_code, 'raw_domain': domain, \
                                'rank': rank, 'func':func, 'ip': ip_address, 'scan_ts': scan_ts, 'round': round}
                ch.basic_publish(
                    exchange='',
                    routing_key=config['rabitmq']['url_result_queue'],  # 告诉rabbitmq将消息发送到 url_result 队列中
                    body=json.dumps(data),  # 发送消息的内容
                    properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                )

            if ('Content-Length' in attack_response.headers and 'Content-Length' in normal_response.headers) and \
                    normal_response.headers.get('Content-Length') != attack_response.headers.get('Content-Length'):
                for value in aheaders.values():
                    if value in attack_response.content.decode('utf-8'):
                        verify_response = s.get(url = url, headers=headers, params=p1 ,verify=False, timeout=25)
                        if value in verify_response.content.decode('utf-8'):
                            data = {'url': url, 'payload': aheaders, 'response': attack_response.status_code, \
                                            'raw_domain': domain, 'rank': rank, 'func':func, 'ip': ip_address, \
                                            'scan_ts': scan_ts, 'round': round}
                            ch.basic_publish(
                                exchange='',
                                routing_key=config['rabitmq']['url_result_queue'],  # 告诉rabbitmq将消息发送到 url_result 队列中
                                body=json.dumps(data),  # 发送消息的内容
                                properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                            )
                        break
        

    except Exception as e:
        traceback.print_exc()
        if 'No address' not in e and 'ConnectTimeoutError' not in e:
            print(f'{url} error: {e}')
        #return




async def wcpdetection_xx(scan_ts, url, round, domain, rank, func, ch, aheaders = {}, param = {}):
    
    buster1 = str(random.randint(1 ,1000000))
    p = {'wpctest' :buster1}
    p.update(param)


    p1 = {'wcptest' :str(random.randint(1 ,1000000))}
    p1.update(param)
    attack_headers = {**headers, **aheaders}


    try:
        timeout = aiohttp.ClientTimeout(total=125)
        async with aiohttp.ClientSession(timeout=timeout, max_field_size=8190 * 2,) as session:
            async with session.get(url = url, headers=headers, params=p, verify_ssl=False) as normal_response:
                print('%s: %s' %(url, normal_response.status))
                if normal_response.status >= 400:
                    await session.close()
                    return
            
            async with session.get(url = url, headers=attack_headers, params=p1, verify_ssl=False) as attack_response:
            
                ip_address = None
                if attack_response and attack_response.connection:
                    peername = attack_response.connection.transport.get_extra_info('peername')
                    ip_address = peername[0] if peername else None

                if normal_response.status != attack_response.status:
                    async with session.get(url = url, headers=headers, params=p1, verify_ssl=False) as verify_response:

                        if attack_response.status == verify_response.status:
                            data = {'url': url, 'payload': aheaders, 'response': attack_response.status, 'raw_domain': domain, \
                                'rank': rank, 'func':func, 'ip': ip_address, 'scan_ts': scan_ts, 'round': round}
                    
                            ch.basic_publish(
                                exchange='',
                                routing_key=config['rabitmq']['url_result_queue'],  # 告诉rabbitmq将消息发送到 url_roll 队列中
                                body=json.dumps(data),  # 发送消息的内容
                                properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                            )
            
                if ('Content-Length' in attack_response.headers and 'Content-Length' in normal_response.headers) and \
                    normal_response.headers['Content-Length'] != attack_response.headers['Content-Length']:
                    for value in aheaders.values():
                        #attack_resp_text = attack_response.content.read().decode("utf8")
                        attack_resp_text = await attack_response.content.read().decode("utf8")
                        if value in attack_resp_text:
                            async with session.get(url=url, headers=headers, params=p1, verify_ssl=False) as verify_response:
                                #verify_resp_text = verify_response.content.read().decode("utf8")
                                verify_resp_text = await verify_response.content.read().decode("utf8")
                                if value in verify_resp_text:
                                    data = {'url': url, 'payload': aheaders, 'response': attack_response.status, \
                                            'raw_domain': domain, 'rank': rank, 'func':func, 'ip': ip_address, \
                                            'scan_ts': scan_ts, 'round': round}
                                    ch.basic_publish(
                                        exchange='',
                                        routing_key=config['rabitmq']['url_result_queue'],  # 告诉rabbitmq将消息发送到 url_roll 队列中
                                        body=json.dumps(data),  # 发送消息的内容
                                        properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                                    )
                                    break

    except asyncio.exceptions.TimeoutError:
        print(f"timeout error on {url}")

    except Exception as e:
        #print('------------ %s:' %(url))
        traceback.print_exc()
        print(f"Exception while fetching {url}: {e}")
        #return


async def mutation_cpdos_HHO(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HHO test: testing...")
    attack_headers = {}
    for i in range(200):
        attack_headers['X-Oversized-Header-{}'.format(i)] = 'Big-Value-0000000000000000000000000000000000'

    await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)

async def mutation_cpdos_HMO(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HMO test: testing...")
    methods = ['GET', 'POST', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'PATCH', 'PUT', 'TRACE', 'NONSENSE']
    headers = ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override']
    for h in headers:
        for m in methods:
            attack_headers = {h: m}
            # print(attack_headers)
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_HTTP_Forwarded_headers(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-Forwarded-headers testing...")
    # HTTP路由头部
    # X-Forwarded-Host X-Forwarded-Port
    attack_headers = {'X-Forwarded-Host': 'attack.com', 'X-Forwarded-Port': '67890'}
    await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)
    # Forwarded -- RFC7239
    header_F = 'Forwarded'
    value_F = ['for="_gazonk"', 'For="[2001:db8:cafe::17]:4711"', 'for=192.0.2.60;proto=http;by=203.0.113.43',
               'for=192.0.2.43, for=198.51.100.17', 'for=127.0.0.1', 'test123']
    for v in value_F:
        attack_headers = {header_F: v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_HTTP_Protocol_headers(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-Protocol-headers testing...")
    # HTTP协议头部
    # X-Forwarded-SSL
    header_XFSSL = 'X-Forwarded-SSL'
    value_XFSSL = ['no', 'off', 'nonsense', 'test123']
    for v in value_XFSSL:
        attack_headers = {header_XFSSL: v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)
    # X-Original-Host
    header_XOHost = 'X-Original-Host'
    value_XOHost = ['attack.com', '123.123.123.123', '127.0.0.1', 'test123']
    for v in value_XOHost:
        attack_headers = {header_XOHost: v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)
    # X-Forwarded-Scheme X-Forwarded-Proto X-Forwarded-Protocol
    header_XFProtocol = ['X-Forwarded-Proto', 'X-Forwarded-Protocol', 'X-Forwarded-Scheme']
    value_XFProtocol = ['http', 'https', 'nohttps', 'ssl', 'nonsense', 'test123']
    for h in header_XFProtocol:
        for v in value_XFProtocol:
            attack_headers = {h: v}
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_Range(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-Range-headers testing...")
    # 范围请求 Range --RFC9110
    # 可以忽略Range头，必须忽略格式错误的Range头，必须忽略不理解的单位，可以忽略两个以上重叠范围的、一组未按升序排列的小范围头，可以忽略所选数据长度为0的范围头
    header_R = 'Range'
    value_R = ['bytes=1-100', 'bytes=100000000-100000010', 'test123', 'test=1-100', 'bytes=test', 'suffix=0-128', \
               'int=1-10', 'bytes=0-100,200-500', 'bytes=0-1000,500-1200', 'bytes=1-1', 'bytes=100-50',
               'bytes=1-50,500-600,100-200,70-80']
    for v in value_R:
        attack_headers = {header_R: v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_If(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-If-headers testing...")
    # 条件请求 -- RFC9110
    # If-Match If-None-Match If-Range
    header_IFM = ['If-Match', 'If-None-Match', 'If-Range']
    value_IFM = ['"12test123"', 'W/"12test123"', 'W/"123abc", "12test"', '*']
    for h in header_IFM:
        for v in value_IFM:
            attack_headers = {h: v}
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)
    # If-Modified-Since If-Unmodified-Since If-Range 必须忽略格式错的日期值，必须忽略修改日期内没有可用的头，请求方法必须是GET或者HEAD
    header_IFMS = ['If-Modified-Since', 'If-Unmodified-Since', 'If-Range']
    value_IFMS = ['Wed, 21 Oct 2015 07:28:00 GMT', 'Sun, 21 Oct 2015 07:28:00 GMT', 'Wed, 77 Oct 2015 07:28:00 GMT',
                  'Sat, 01 Oct 1970 07:28:00 GMT', \
                  'Wed, 21 Oct 2015 66:66:66 GMT', 'WED, 21 OCT 2015 07:28:00 GMT', 'Wed, 20 Oct 2100 07:28:00 GMT',
                  'test123']
    for h in header_IFMS:
        for v in value_IFMS:
            attack_headers = {h: v}
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)



async def mutation_cpdos_upgrade(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-upgrade-headers testing...")
    header_up = 'Upgrade'
    value = ['HTTP/3.0', 'HTTP/0.9', 'Websocket']
    connection = 'Connection'
    cvalue = 'upgrade'
    # temp_header = add_header(request, connection, cvalue)
    # 有connection
    for v in value:
        attack_headers = {header_up: v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)
    # 无connection


async def mutation_cpdos_identify(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-HTTP-identify-headers testing...")
    header_ID = ['Authorization', 'X-Authorization', 'X-Auth-User', 'Auth-Key', 'Client-Proxy-Auth-Required',
                 'Proxy-Authorization']
    value = ['Basic dGVzdCUzQTEyMw==', 'Basic test123', 'HOBA dGVzdCUzQTEyMw==', 'test 123']
    for h in header_ID:
        for v in value:
            attack_headers = {h: v}
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_cdn(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-cdn testing...")
    header_CDN = ['Fastly-Client-Ip', 'Fastly-Soc-X-Request-Id', 'X-Amz-Website-Redirect-Location',
                  'X-Amz-Server-Side-Encryption', 'X-Amzn-CDN-Cache']
    value = '123567965436436'
    for h in header_CDN:
        attack_headers = {h: value}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


async def mutation_cpdos_transfer_encoding(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-transfer-encoding testing...")
    header_TE = ['Accept', 'Accept-Encoding', 'Transfer-Encoding']
    value = ['test123', 'gzip']
    for h in header_TE:
        for v in value:
            attack_headers = {h: v}
            await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)



# 畸形头部
chars = [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']
async def mutation_cpdos_HMC(scan_ts, url, round, domain, rank, func, ch):
     new_header = 'x-metachar'
     value = 'test123'
     for c in chars:
        attack_headers1 = {c + new_header: value}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers1)
        attack_headers2 = {new_header + c: value}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers2)
        attack_headers3 = {new_header: value + c}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers3)



async def mutation_cpdos_Other_headers(scan_ts, url, round, domain, rank, func, ch):
    print("cpdos-Other-headers testing...")
    header_ = {'Downlink': '65535', 'DPR': '10000.0', 'Early-Data': '1', 'ECT': 'slow-2g', 'ECT': '100g',
               'Max-Forwards': '1', 'Origin': '127.0.0.1', 'Origin': 'https://127.0.0.1',
               'Origin': 'https://attack.com',
               'Pragma': 'no-cache', 'RTT': '1', 'RTT': '123456789', 'Save-Data': 'on', 'Save-Data': 'off',
               'Save-Data': 'test',
               'Pragma': 'test123', 'Referer': 'https://127.0.0.1', 'Referer': 'https://attack.com',
               'Referer': '127.0.0.1',
               'Sec-CH-Prefers-Color-Scheme': 'dark', 'Sec-CH-Prefers-Color-Scheme': 'test123',
               'Sec-CH-Prefers-Reduced-Motion': 'reduce', 'Sec-CH-Prefers-Reduced-Motion': 'test123',
               'sec-CH-Prefers-Reduced-Transparency': 'reduce',
               'sec-CH-UA': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
               'sec-CH-UA-Arch': 'x86',
               'sec-CH-UA-Bitness': '32',
               'Sec-CH-UA-Full-Version': '96.0.4664.93',
               'sec-CH-UA-Full-version-List': '" Not A;Brand";v="99.0.0.123456789", "Chromium";v="98.0.4750.0", "Google Chrome";v="98.0.4750.0"',
               'Sec-CH-UA-Mobile': '?1',
               'sec-CH-UA-Model': '"Pixel 3 XL"',
               'sec-CH-UA-Platform' :	'"Andriod"'	,
               'sec-CH-UA-Platform-Version'	:	'11.11.11.11'	,
               'sec-Fetch-Dest'	:	'video'	,
               'sec-Fetch-Mode'	:	'cors'	,
               'Sec-Fetch-site'	:	'none'	,
               'sec-Fetch-User'	:	'?0'	,
               'sec-CH-Prefers-Reduced-Transparency'	:	'test123'	,
               'sec-CH-UA'	:	'test123'	,
               'sec-CH-UA-Arch'	:	'test123'	,
               'sec-CH-UA-Bitness'	:	'test123'	,
               'Sec-CH-UA-Full-Version'	:	'test123'	,
               'sec-CH-UA-Full-version-List'	:	'test123'	,
               'Sec-CH-UA-Mobile'	:	'test123'	,
               'sec-CH-UA-Model'	:	'test123'	,
               'sec-CH-UA-Platform' 	:	'test123'	,
               'sec-CH-UA-Platform-Version'	:	'test123',
               'sec-Fetch-Dest'	:	'test123'	,
               'sec-Fetch-Mode'	:	'test123'	,
               'Sec-Fetch-site'	:	'test123'	,
               'sec-Fetch-User'	:	'test123'	,
               }

    await wcpdetection(scan_ts, url, round, domain, rank, func, ch, header_)

async def mutation_fat_get(scan_ts, url, round, domain, rank, func, ch):
    print("fat get testing...")
    header_FG = ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override']
    value = 'POST'
    for h in header_FG:
        attack_headers = {h:value}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)

async def mutation_black_list(scan_ts, url, round, domain, rank, func, ch):
    print("blacklist testing...")
    with open('blacklist.txt', 'r') as f:
        value = f.read().split('\n')
    for v in value:
        attack_headers = {'blheader': v}
        await wcpdetection(scan_ts, url, round, domain, rank, func, ch, attack_headers)


def callback(ch, method, properties, body, custom_channel, loop):
    loop.run_until_complete(main(body, custom_channel))

async def main(body, custom_channel):
    task_message = json.loads(body)
    print(task_message)
    func_name = task_message['func']
    url = task_message.get('url', '')
    domain = task_message.get('raw_domain', '')
    rank = task_message.get('rank', -1)
    round = task_message.get('round', -1)
    scan_ts = task_message.get('scan_ts', -1)
    # 简单的函数映射，可以用更复杂的逻辑替换
    func = globals().get(func_name)     

    if func and len(url) > 0:
        try:
            await func(scan_ts, url, round, domain, rank, func_name, custom_channel)
        except:
            pass



def load_config(file_path):
    """加载 JSON 配置文件"""
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config


config = load_config("config.json")
credentials = pika.PlainCredentials(
    username=config['rabitmq']['username'],
    password=config['rabitmq']['password']
)

def read_json(path):
    with open(path, 'r') as f:
        data = json.load(f)
    return data
cnt = 1


def sort_strings_by_number(strings):
  split_strings = [(int(x.split('_')[0]), x) for x in strings]
  sorted_strings = sorted(split_strings, key=lambda x: x[0])
  return [x[1] for x in sorted_strings]


def wcp_check():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        try:

            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    heartbeat=config['rabitmq']['heartbeat'],
                    host=config['rabitmq']['host'],  # MQ地址(本机)
                    port=config['rabitmq']['port'],  # 端口号,注意是5672,不是15672
                    virtual_host=config['rabitmq']['virtual_host'],  # 虚拟主机
                    credentials=credentials,  # 用户名/密码
                )
            )

            channel_result = connection.channel()
            channel_result.queue_declare(
                queue=config['rabitmq']['url_result_queue'],  # 队列名
                durable=True,  # 使队列持久化
            )

            channel_wcp = connection.channel()
            channel_wcp.queue_declare(
                queue=config['rabitmq']['url_wcp_queue'],  # 队列名
                durable=True,  # 使队列持久化
            )
    
            channel_wcp.basic_consume(
                queue=config['rabitmq']['url_wcp_queue'],  # 对列名
                auto_ack=True,  # 自动回应
                on_message_callback=lambda ch, method, properties, body: callback(ch, method, properties, body, channel_result, loop),
            )
            channel_wcp.start_consuming()

        except:
            try:
                if connection:
                    connection.close()
            except:
                pass
            traceback.print_exc()


if __name__ == "__main__":


    try:

        futures = []
        for i in range(10):
            p = multiprocessing.Process(target=wcp_check)
            p.start()
            futures.append(p)

        for future in futures:
            future.join()

    except:
        traceback.print_exc()
        print(' [*] Exiting...')
