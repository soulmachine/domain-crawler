#!/usr/bin/env python3
from datetime import datetime
import pymongo
import sys
import threading
import time
import queue
from whois import NICClient
import socks
from stem import Signal
from stem.control import Controller


SCAN_INTERVAL = 180  # days

mongo_client = pymongo.MongoClient('localhost', 27017)
db = mongo_client.domain

NUM_THREADS = 1
q = queue.Queue()

change_ip_lock = threading.RLock()


def worker():
    while True:
        domain = q.get()
        if domain is None:
            break
        query(domain)
        q.task_done()


def change_ip():
    with change_ip_lock:
        with Controller.from_port(port = 9051) as controller:
            controller.authenticate(password = 'tor123456')
            controller.signal(Signal.NEWNYM)
        time.sleep(5)  # wait for the tor node


def is_valid(tld, text):
    if text.find('For more information on Whois status codes') != -1:
        return True
    if tld == 'ai' and text.startswith('DOMAIN INFORMATION'):
        return True
    if text.startswith('Reserved by Registry'):
        return True
    return False


def query(domain):
    domain = domain.lower()
    tld = domain[(domain.find('.') + 1):]
    target = tld + '_domains'
    record = db[target].find_one({'_id': domain}, {'_id': 1, 'updatedAt': 1})
    if record is not None:  # existed
        days = (datetime.now() - record['updatedAt']).days
        if days < SCAN_INTERVAL:  # last query was within SCAN_INTERVAL days
            print(domain + ' was already queried in recent %d days' % days)
            return False
    print('Querying ' + domain)
    nic_client = NICClient()
    options = {'proxy': {
        'type': socks.SOCKS5,
        'host': 'localhost',
        'port': 9050
    }}
    text = nic_client.whois_lookup(options, domain, 0)
    if 'limit exceeded' in text.lower() or len(text) < len(domain):
        print('whois limit exceeded, received: ' + text)
        change_ip()
        q.put(domain)
        return False
    elif 'No match for' in text or 'not registered' in text or 'NOT FOUND' in text:  # not registered
        if record is None:  # insert
            db[target].insert({'_id': domain, 'registered': False, 'createdAt': datetime.now(), 'updatedAt': datetime.now()})
        else:  # update
            db[target].update({'_id': domain}, {'$set': {'registered': False, 'updatedAt': datetime.now(), 'rawInfo': None}})
        print(domain + ' is not registered')
        return False
    elif is_valid(tld, text):
        pos = text.find('For more information on Whois status codes')
        if pos != -1:  # remove garbage text
            text = text[0 : pos]
        if record is None:  # insert
            info = {
                '_id': domain,
                'registered': True,
                'createdAt': datetime.now(),
                'updatedAt': datetime.now(),
                'rawInfo': text
            }
            db[target].insert(info)
        else:  # update
            if (datetime.now() - record['updatedAt']).days > 30:  # last query was within 30 days
                db[target].update({'_id': domain}, {'$set': {'registered': True, 'updatedAt': datetime.now(), 'rawInfo': text}})
        print(domain + ' is registered, ' + text[: 60])
        return True
    elif 'in process of registration, try again later' in text:
        print(text)
        return False
    else:
        raise ValueError(text)
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
    if len(sys.argv) != 5 and len(sys.argv) != 3:
        print(sys.argv[0] + ' <word_file> <tld> [prefix_suffix] [prefix | suffix]')
        sys.exit(1)

    tld = sys.argv[2]
    if len(sys.argv) == 5:
        prefix_suffix = sys.argv[3]
        suffix = sys.argv[4] == 'suffix'
    else:
        prefix_suffix = ''
        suffix = True
    with open(sys.argv[1], 'r') as f:
        lines = [line.strip().lower() for line in f.readlines()]
    query2(lines, prefix_suffix, suffix, tld)
