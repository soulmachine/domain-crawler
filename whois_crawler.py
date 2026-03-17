#!/usr/bin/env python3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
import socks
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller

from db import get_db
from whois import NICClient

SCAN_INTERVAL = 180  # days

db = get_db()

NUM_THREADS = 1

change_ip_lock = threading.RLock()

SOCKS_PROXY = {'host': 'localhost', 'port': 9050}


def change_ip():
    with change_ip_lock:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate(password='tor123456')
            controller.signal(Signal.NEWNYM)
        time.sleep(5)  # wait for the tor node


def get_record(target, domain):
    return db.get_record(target, domain)


def should_skip(domain, record):
    if record is not None:
        days = (datetime.now() - record['updatedAt']).days
        if days < SCAN_INTERVAL:
            print(domain + ' was already queried in recent %d days' % days)
            return True
    return False


def save_result(target, record, domain, registered, raw_info=None):
    if record is None:
        db.insert(target, domain, registered, raw_info)
    else:
        db.update(target, domain, registered, raw_info)


def is_valid(tld, text):
    if 'No match for' in text or 'not registered' in text or 'NOT FOUND' in text or 'Domain not found' in text:  # not registered
        return False
    elif 'For more information on Whois status codes' in text:
        return True
    elif 'The registration of this domain is restricted' in text:
        return True
    elif 'in process of registration, try again later' in text:
        return False

    if tld == 'ai' and text.startswith('DOMAIN INFORMATION'):
        return True
    if tld == 'finance':
        if (text.startswith('Domain Name:') or 'domain is available for purchase' in text):
            return True
        elif text.startswith('This name is reserved'):
            return True
        elif 'The registration of this domain is restricted' in text:
            return False
        else:
            raise ValueError(text)
    if text.startswith('Reserved by Registry'):
        return True
    raise ValueError(text)


def query_ai_http(domain, target, record):
    """Query .ai domains via HTTP scraping."""
    socks_proxies = {
        'http': 'socks5://localhost:9050',
        'https': 'socks5://localhost:9050',
    }
    r = requests.post(
        'https://whois.ai/cgi-bin/newdomain.py',
        data={'domain': domain},
        verify=False,
        proxies=socks_proxies,
    )
    if 'not registered' in r.text:
        save_result(target, record, domain, registered=False)
        return False
    elif 'already registered' in r.text:
        soup = BeautifulSoup(r.content, 'lxml')
        raw_info = None
        tmp = soup.select('table pre')
        if len(tmp) > 0:
            raw_info = tmp[0].text
        save_result(target, record, domain, registered=True, raw_info=raw_info)
        return True
    else:
        print('whois limit exceeded')
        change_ip()
        return False


def query_whois_socket(domain, tld, target, record):
    """Query domains via socket-based whois."""
    nic_client = NICClient()
    options = {'proxy': {
        'type': socks.SOCKS5,
        'host': SOCKS_PROXY['host'],
        'port': SOCKS_PROXY['port'],
    }}
    text = nic_client.whois_lookup(options, domain, 0)

    if 'limit exceeded' in text.lower() or len(text) < len(domain):
        print('whois limit exceeded, received: ' + text)
        change_ip()
        return False

    registered = is_valid(tld, text)

    pos = text.find('For more information on Whois status codes')
    if pos != -1:
        text = text[0:pos]

    save_result(target, record, domain, registered=registered, raw_info=text)


def query(domain):
    domain = domain.lower()
    tld = domain[(domain.find('.') + 1):]
    target = tld + '_domains'
    record = get_record(target, domain)
    if should_skip(domain, record):
        return False

    print('Querying ' + domain)

    if tld == 'ai':
        return query_ai_http(domain, target, record)
    else:
        return query_whois_socket(domain, tld, target, record)


def query2(word_list, prefix_suffix, suffix=True, tld='com'):
    """ Query two words combinations

      :param word_list: all English words English word list https://github.com/first20hours/google-10000-english
      :param prefix_suffix:  prefix or suffix
      :tld  domain prefix, com, net, org
      :param suffix: True by default
      :return: None
    """
    domains = [
        word + prefix_suffix + '.' + tld if suffix else prefix_suffix + word + '.' + tld
        for word in word_list
    ]
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        executor.map(query, domains)


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
