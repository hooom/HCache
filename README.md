# Hcache
*HCache* is a open-source testing tool to facilitates the widespread identification of Web Cache Poisoning (WCP) vulnerabilities. 
![Overview](./img/hcache.png)

## Prepare
* Install Redis, please see [Install Doc](https://redis.io/docs/latest/operate/oss_and_stack/install/install-redis/)
* Install RabitMQ, please see [Install Doc](https://www.rabbitmq.com/docs/download)
* config config.json

## Usage
* step 0: pip3 install -r requirements.txt
* step 1: python3 url_seed_init.py top-1m.csv
* step 2: nohup python3 url_extend.py > extend.log & 
* step 3: nohup python3 url_wcp_test.py > result.log &



## How to cite us?
This framework is based on our latest research, **Internet’s Invisible Enemy: Detecting and Measuring Web Cache Poisoning in the Wild**, accepted at ACM CCS '24.

If you want to cite us, please use the following (BibTeX) reference:
```
@INPROCEEDINGS {liang2024webcachepoisoning,
    title = {Internet’s Invisible Enemy: Detecting and Measuring Web Cache Poisoning in the Wild},
    author = {Y. Liang and J. Chen and R. Guo and K. Shen and H. Jiang and M. Hou and Y. Yu and H. Duan},
    journal={ACM Conference on Computer and Communications Security (CCS)},
    year = {2024},
    issn = {979-8-4007-0636-3/24/10},
    doi = {10.1145/3658644.3690361},
    url = {https://doi.org/10.1145/3658644.3690361},
    address = {Salt Lake City, UT, USA},
    month = {october}
}
```


## Disclaimer
Please refrain from using these tools for any unlawful purposes. The author assumes no responsibility for illegal actions. Misusing the provided information may lead to legal consequences.
