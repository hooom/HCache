import os
import json
import sys
import string
import pika
import traceback
import time
import redis
import pandas as pd



def load_config(file_path):
    """加载 JSON 配置文件"""
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config


# 格式化URL,有限考虑https
def format_url(url):
    if "://" not in url:
        url = 'https://{}'.format('www.' + url)
    return url


def cache_url_key(url):
    # 测试连接，设置和获取一个键值对
    client_db0.set(url, 1, ex=3600)

        

if __name__ == "__main__":
    config = load_config("config.json")

    # Redis connection, db0 for caching top 1k domain
    client_db0 = redis.StrictRedis(host=config['redis']['host'], port=config['redis']['port'], password=config['redis']['password'], db=0)


    credentials = pika.PlainCredentials(
        username=config['rabitmq']['username'],
        password=config['rabitmq']['password'],
    )

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            heartbeat=config['rabitmq']['heartbeat'],
            host = config['rabitmq']['host'], # MQ地址(本机)
            port = config['rabitmq']['port'], # 端口号
            virtual_host = config['rabitmq']['virtual_host'], # 虚拟主机
            credentials = credentials, # 用户名/密码
        )
    )

    channel_init = connection.channel()
    channel_init.queue_declare(
        queue=config['rabitmq']['url_find_queue'],  # 队列名
        durable=True,  # 使队列持久化
    )   

    input_path = sys.argv[1]
    
    # remove cache
    client_db0.flushdb()

    dd = pd.read_csv(input_path, sep=',', names=['rank', 'domain'])
    dd['url'] = dd['domain'].apply(format_url)
    
    # get top1K domain
    r = dd[dd['rank'] <= 1000]
    h = r.drop_duplicates().T.drop_duplicates().T

    for index, row in r.iterrows():
        domain = row['domain']
        rank = int(row['rank'])

        url = row['url']
        scan_ts = int(time.time())
        result = {'raw_domain': domain, 'rank': rank, 'url': url, 'round': 0, 'scan_ts':scan_ts}
        
        if not client_db0.exists(url):
            channel_init.basic_publish(
                exchange='',
                routing_key=config['rabitmq']['url_find_queue'],  # 告诉rabbitmq将消息发送到 url_roll 队列中
                body=json.dumps(result),  # 发送消息的内容
                properties=pika.BasicProperties(delivery_mode=2, )  # 消息持久化
            )
            cache_url_key(url)




