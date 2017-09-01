#!/usr/bin/env python3
from datetime import datetime
import requests
import pymongo
import sys
import threading
import queue
from bs4 import BeautifulSoup

SCAN_INTERVAL = 180  # days

mongo_client = pymongo.MongoClient('localhost', 27017)
db = mongo_client.domain

NUM_THREADS = 2
q = queue.Queue()


from stem import Signal
from stem.control import Controller

def change_ip():
    with Controller.from_port(port = 9051) as controller:
        controller.authenticate(password = 'tor123456')
        controller.signal(Signal.NEWNYM)


def worker():
    while True:
        domain = q.get()
        if domain is None:
            break
        query(domain)
        q.task_done()


def query(domain):
    domain = domain.lower()
    record = db.domains.find_one({'_id': domain}, {'_id': 1, 'updatedAt': 1})
    if record is not None:  # existed
        days = (datetime.now() - record['updatedAt']).days
        if days < SCAN_INTERVAL:  # last query was within SCAN_INTERVAL days
            return False

    print('Querying ' + domain)
    socks_proxies = { 'http': 'socks5://localhost:9050', 'https': 'socks5://localhost:9050' }
    r = requests.post('https://whois.ai/cgi-bin/newdomain.py', data = {'domain': domain}, verify=False, proxies=socks_proxies)
    if 'not registered' in r.text:
        if record is None:  # insert
            db.domains.insert({'_id': domain, 'registered': False, 'createdAt': datetime.now(), 'updatedAt': datetime.now()})
        else:  # update
            db.domains.update({'_id': domain}, {'$set': {'registered': False, 'updatedAt': datetime.now(), 'rawInfo': None}})
        return False
    elif 'already registered' in r.text:
        soup = BeautifulSoup(r.content, 'lxml')
        info = {
            '_id': domain,
            'registered': True,
            'createdAt': datetime.now(),
            'updatedAt': datetime.now(),
        }
        tmp = soup.select('table pre')
        if len(tmp) > 0:
            info['rawInfo'] = soup.select('table pre')[0].text
        if record is None:  # insert
            db.domains.insert(info)
        else:
            if (datetime.now() - record['updatedAt']).days > 30:  # last query was within 30 days
                db.domains.update({'_id': domain}, {'$set': {'registered': True, 'updatedAt': datetime.now(), 'rawInfo': text}})
        return True
    else: # whois limit exceeded
        # raise ValueError(r.text)
        print('whois limit exceeded')
        change_ip()
        q.put(domain)
        return False


def query2(word_list, prefix_suffix, suffix=True, tld='com'):
    """ Query two words combinations

      :param word_list: all English words English word list https://github.com/first20hours/google-10000-english
      :param prefix_suffix:  prefix or suffix
      :tld  domain prefix, com, net, org
      :param suffix: True by default
      :return: None
    """
    threads = []
    for i in range(NUM_THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for word in word_list:
        domain = word + prefix_suffix + '.' + tld if suffix else prefix_suffix + word + '.' + tld
        q.put(domain)
    # block until all tasks are done
    q.join()
    # stop workers
    for i in range(NUM_THREADS):
        q.put(None)
    for t in threads:
        t.join()


if __name__ == '__main__':
    if len(sys.argv) != 4 and len(sys.argv) != 2:
        print(sys.argv[0] + ' <word_file> [prefix_suffix] [prefix | suffix]')
        sys.exit(1)

    tld = 'ai'
    if len(sys.argv) == 4:
        prefix_suffix = sys.argv[2]
        suffix = sys.argv[3] == 'suffix'
    else:
        prefix_suffix = ''
        suffix = True
    with open(sys.argv[1], 'r') as f:
        lines = [line.strip().lower() for line in f.readlines()]
    query2(lines, prefix_suffix, suffix, tld)
