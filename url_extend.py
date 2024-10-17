import requests
from multiprocessing import Pool, Manager
from bs4 import BeautifulSoup
import asyncio
import asyncpool
import logging
import functools
import os
import json
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import random
import string
import urllib
from urllib import parse as urlparse
from urllib.parse import unquote
from simhash import Simhash
import pika
import json
import socket
import traceback
import multiprocessing
import threading
import time
import redis
import asyncio
from concurrent.futures import ProcessPoolExecutor
import aiohttp
from urllib.parse import urljoin
from lxml import etree
import chardet
from concurrent.futures import as_completed


keys = ["cache-control", "pragma", "x-cache-status", "x-cache", "cf-cache-status", "x-drupal-cache",
                "x-varnish-cache", "akamai-cache-status", "server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status",
                "x-proxy-cache", "x-cache-hits", "x-cache-result", "age", "x-cache-lookup", "x-cc-via", "x-rack-cache"]


def load_config(file_path):
    """加载 JSON 配置文件"""
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config



requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

config = load_config("config.json")

# 创建 Redis 连接
client_db0 = redis.StrictRedis(host=config['redis']['host'], port=config['redis']['port'], password=config['redis']['password'], db=0)
client_db1 = redis.StrictRedis(host=config['redis']['host'], port=config['redis']['port'], password=config['redis']['password'], db=1)



credentials = pika.PlainCredentials(
    username=config['rabitmq']['username'],
    password=config['rabitmq']['password'],
)


headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "iframe", "Accept-Encoding": "gzip, deflate",
    "Sec-Fetch-Mode": "navigate",
    "sec-ch-ua": "\"Google Chrome\";v=\"95\", \"Chromium\";v=\"95\", \";Not A Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "sec-ch-ua-platform": "\"macOS\"",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
cookies = {"demdex": "20805764189595439791938557290460760295", "dextp": "771-1-1651031946872|1123-1-1651031946974"}

Chars = [',', '-', '_']


def url_etl(url):
    '''
    url泛化处理
    :param url: 原始url
    :return: 处理过后的url
    '''
    params_new = {}
    u = urlparse.urlparse(url)
    query = unquote(u.query)
    if not query:
        return url
    path = unquote(u.path)
    params = urlparse.parse_qsl(query, True)
    for k, v in params:
        if v:
            params_new[k] = etl(v)
    query_new = urllib.parse.urlencode(params_new)
    url_new = urlparse.urlunparse(
        (u.scheme, u.netloc, u.path, u.params, query_new, u.fragment))
    # print url_new
    return url_new


def etl(str):
    '''
    传入一个字符串，将里面的字母转化为A，数字转化为N，特殊符号转换为T，其他符号或者字符转化成C
    :param str:
    :return:
    '''
    chars = ""
    for c in str:
        c = c.lower()
        if ord('a') <= ord(c) <= ord('z'):
            chars += 'A'
        elif ord('0') <= ord(c) <= ord('9'):
            chars += 'N'
        elif c in Chars:
            chars += 'T'
        else:
            chars += 'C'
    return chars


def url_compare(url, link):
    try:
        dis = Simhash(url).distance(Simhash(link))
        if -2 < dis < 15:
            return True
        else:
            return False
    except:
        return False


def reduce_urls(ori_urls):
    '''
    对url列表去重
    :param ori_urls: 原始url列表
    :return: 去重后的url列表
    '''
    etl_urls = []
    result_urls = []
    for ori_url in ori_urls:
        etl = url_etl(ori_url)
        # print(etl)
        score = 0
        if etl_urls:
            for etl_url in etl_urls:
                if not url_compare(etl, etl_url):
                    score += 1

            if score == len(etl_urls):
                result_urls.append(ori_url)
                etl_urls.append(etl)
        else:
            etl_urls.append(etl)
            result_urls.append(ori_url)

    return result_urls


def save_json(data, path):
    data = json.dumps(data)
    with open(path, 'w') as f:
        f.write(data)


def ranstring(num):
    salt = ''.join(random.sample(string.ascii_letters + string.digits, num))
    return salt


async def check_cache(session, url):
    async with session.get(url, headers=headers, cookies=cookies, verify_ssl=False, timeout=5) as response:
        if response.status == 200:
            check_cache(response, url)

def check_cache(response, url):
    origin_domain = url.split('//')[1].split('/')[0]
    origin_schema = url.split("://")[0] + "://"
    try:
        for k in response.headers:
            if k.lower() in keys:
                # 处理重定向问题
                reditList = response.history
                if len(reditList):
                    location = reditList[len(reditList) - 1].headers["location"]
                    if location.startswith('https://') or location.startswith('http://'):
                        url = location
                    elif location.startswith("//"):
                        url = origin_schema + location
                    elif location.startswith('/'):
                        url = origin_schema + origin_domain + location
                    else:
                        raise
                return url
        return None
    except:
        return None


# 一次递归
def add_urls(origin_urls, new_url):
    if not new_url:
        return None, None
    origin_domain = origin_urls.split('//')[1].split('/')[0]
    origin_schema = origin_urls.split("://")[0] + "://"
    if new_url.startswith('https://') or new_url.startswith('http://'):
        new_domain = new_url.split('//')[1].split('/')[0]
        return new_domain, new_url
    if new_url.startswith('//'):
        new_domain = new_url.split('//')[1].split('/')[0]
        new_url = origin_schema + new_url.split('//')[1]
        return new_domain, new_url
    if new_url.startswith('/'):
        new_domain = origin_domain
        new_url = origin_schema + origin_domain + new_url
        return new_domain, new_url
    # print(new_url)
    return None, None


# 一个域名下选择60个静态资源
async def get_cache_urls(urls):
    data = []

    for url in urls:
        if '.pdf' in url or '.mp4' in url:
            continue
        # 忽略所有非js,css,xml,png 等静态资源 首页也可以保留
        if str(url).isdigit():
            continue
        file_name = os.path.basename(url).split('?')[0]
        if '.' in file_name:
            # print(url)
            try:
                async with aiohttp.ClientSession() as session:
                    url = await check_cache(session, url)
                    if not url:
                        continue
                    # 忽略参数后面数值
                    have_in = False
                    tmp_url = url.split('?')[0]
                    for i in data:
                        if tmp_url in i[0]:
                            have_in = True
                            break
                    if not have_in:
                        data.append(tmp_url)
                # 静态文件只尝试 60个
                if len(data) > 10:
                    return data
            except:
                pass
    return data


async def fetch_html(session, url):
    """使用 aiohttp 发送 HTTP GET 请求，并获取页面 HTML 内容。"""
    has_cache = None
    try:
        async with session.get(url, headers=headers, cookies=cookies, verify_ssl=False, timeout=25) as response:

            if response.status == 200:
                has_cache = check_cache(response, url)
                return await response.text("utf-8","ignore"), has_cache
            else:
                new_url = url
                if "https://" in url:
                    # 尝试HTTP
                    new_url = url.replace("https://", 'http://')
                elif "http://" in url:
                    new_url = url.replace("http://", 'https://')
                else:
                    return None, has_cache
                
                async with session.get(new_url, cookies=cookies, headers=headers, verify_ssl=False, timeout=25) as response:
                    if response.status == 200:
                        has_cache = check_cache(response, url)
                        return await response.text("utf-8","ignore"), has_cache
                return None, has_cache
    except Exception as e:
        #await session.close()
        traceback.print_exc()
        print(f"Exception while fetching {url}: {e}")
        return None, has_cache


async def extract_urls(html, base_url):
    tree = etree.HTML(html)
    links = tree.xpath('//a/@href')
    urls = set()
    for link in links:
        urls.add(link)

    links = tree.xpath('//link/@href')
    for link in links:
        urls.add(link)
    
    links = tree.xpath('//script/@href')
    for link in links:
        urls.add(url)
    return urls


def extract_urls_bs(html, base_url):
    """使用 BeautifulSoup 从 HTML 中提取所有链接，并将其标准化。"""
    print("extract urls ......")
    print(len(html))
    soup = BeautifulSoup(html, 'lxml')
    print("extract done ......")
    urls = set()
    for link in soup.find_all('a', href=True):
        # 标准化并解决相对 URL
        url = urljoin(base_url, link['href'])
        urls.add(url)

    for link in soup.find_all('link', href=True):
        # 标准化并解决相对 URL
        url = urljoin(base_url, link['href'])
        urls.add(url)
    
    for link in soup.find_all('script', href=True):
        # 标准化并解决相对 URL
        url = urljoin(base_url, link['href'])
        urls.add(url)

    return urls

async def crawl_page(session, url):
    """抓取单个页面的所有链接。"""
    print(f"Fetching {url}")
    html, has_cache = await fetch_html(session, url)

    if html:
        urls = await extract_urls(html, url)
        print(f"Found {len(urls)} URLs on {url}")
        return urls, has_cache
    return set(), has_cache

async def find_more_url(url):
    has_cache = None
    try:
        async with aiohttp.ClientSession() as session:
            found_urls, has_cache = await crawl_page(session, url)
            filter_urls = []
            
            for u in found_urls:
                if u not in filter_urls:
                    filter_urls.append(u)
            result = {}
            origin_domain = url.split('//')[1].split('/')[0]
            result[origin_domain] = [url]

            for url_new in filter_urls:
                k, v = add_urls(url, url_new)
                if k is None:
                    continue
                if k not in result:
                    result[k] = [v]
                else:
                    if v not in result[k]:
                        result[k].append(v)

            return result, has_cache
    except:
        
        return {}, has_cache



def merge(x, y):
    return {**x, **y}


# 格式化URL,有限考虑https
def format_url(url):
    if "://" not in url:
        url = 'https://{}'.format(url)
    return url


def cache_url_key(url):
    # 测试连接，设置和获取一个键值对
    client_db0.set(url, 1, ex=3600)

def cache_url_cache_key(url):
    # 测试连接，设置和获取一个键值对
    client_db1.set(url, 1, ex=3600)


def callback(ch, method, properties, body, channel_clean, channel_cache, loop):
    loop.run_until_complete(main(body, channel_clean, channel_cache))
    #asyncio.run_coroutine_threadsafe(main(body, channel_clean, channel_cache), loop)
        

async def main(body, channel_extend, channel_cache):
    data = json.loads(body.decode())
    print(data)
    raw_domain = data['raw_domain']
    rank = data['rank']
    url = data['url']
    round = data['round']
    scan_ts = data['scan_ts']
    if round < 10:
        domain_urls_more, has_cache = await find_more_url(url)
        # clean raw url format
        for domain, urls in domain_urls_more.items():
            for i in range(len(urls)):
                if '</a>' in urls[i]:
                    index = urls[i].find('">')
                    if index > 0:
                        urls[i] = urls[i][:index]
            urls_clean = reduce_urls(urls)
            # filter cache urls
            urls_cache = await get_cache_urls(urls_clean)

            if url not in urls_cache:
                urls_cache.append(url)

            for url in urls_clean:
                clean_result = {'scan_ts': scan_ts, 'raw_domain': raw_domain, 'rank': rank, 'url': url, 'round': round + 1}
                if not client_db0.exists(url):
                    channel_extend.basic_publish(
                        exchange='',
                        routing_key=config['rabitmq']['url_find_queue'],  # 告诉rabbitmq将消息发送到 url 扩展队列中
                        body=json.dumps(clean_result),  # 发送消息的内容
                        properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                    )
                    cache_url_key(url)

        
            for url in urls_cache:
                for func in config['mutation_func']:

                    cache_result = {'scan_ts': scan_ts, 'raw_domain': raw_domain, 'rank': rank, 'url': url, 'func': func, 'round': round}

                    if not client_db1.exists(url+func):
                        channel_cache.basic_publish(
                            exchange='',
                            routing_key=config['rabitmq']['url_wcp_queue'],  # 告诉rabbitmq将消息发送到 url 缓存污染待检测 队列中
                            body=json.dumps(cache_result),  # 发送消息的内容
                            properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
                        )
                        cache_url_cache_key(url+func)



def url_process():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        try:

            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    heartbeat=config['rabitmq']['heartbeat'],
                    host=config['rabitmq']['host'],  # MQ地址(本机)
                    port=config['rabitmq']['port'],  # 端口号,注意是5672
                    virtual_host=config['rabitmq']['virtual_host'],  # 虚拟主机
                    credentials=credentials,  # 用户名/密码
                )
            )

            channel_find = connection.channel()
            channel_find.queue_declare(
                queue=config['rabitmq']['url_find_queue'],  # 队列名
                durable=True,  # 使队列持久化
            )

            channel_extend = connection.channel()
            channel_extend.queue_declare(
                queue=config['rabitmq']['url_find_queue'],  # 队列名
                durable=True,  # 使队列持久化
            )

            channel_cache = connection.channel()
            channel_cache.queue_declare(
                queue=config['rabitmq']['url_wcp_queue'],  # 队列名
                durable=True,  # 使队列持久化
            )

            channel_find.basic_consume(
                queue=config['rabitmq']['url_find_queue'],  # 对列名
                auto_ack=True,  # 自动回应
                on_message_callback=lambda ch, method, properties, body: callback(ch, method, properties, body, channel_extend, channel_cache, loop),
            

            )

            channel_find.start_consuming()
        except:
            if connection:
                connection.close()
            pass


if __name__ == "__main__":

    try:
        futures = []
        
        for i in range(30):
            p = multiprocessing.Process(target=url_process)
            futures.append(p)
            p.start()

        for p in futures:
            p.join()


    except:
        traceback.print_exc()
        print(' [*] Exiting...')



