#!/usr/bin/env python3
import logging
import os
import pytz
import resource
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import socks
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller

from db import get_db
from whois import NICClient

SCAN_INTERVAL = 180  # days

db = get_db()

# Raise the open file descriptor limit (macOS defaults to 256, too low for a crawler)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 8192), hard))

NUM_THREADS = os.cpu_count()

change_ip_lock = threading.RLock()

SOCKS_PROXY = {'host': 'localhost', 'port': 9050} # Can be override by the SOCKS_PROXY envrionment variable

# Configure logging
LOG_FILE = os.getenv('LOG_FILE', 'whois_crawler.log')
# Setup logging with LA timezone
logging.Formatter.converter = lambda self, t: datetime.fromtimestamp(t, tz=pytz.timezone('America/Los_Angeles')).timetuple()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ]
)
logger = logging.getLogger(__name__)

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
            logger.info(domain + ' was already queried in recent %d days' % days)
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
    """Query .ai domains via HTTP scraping using curl through SOCKS proxy."""
    # Equivalent to the command:
    # curl --socks5 192.168.31.187:9050 -X POST "http://whois.nic.ai/" -d "Query=openclaw.ai&QueryType=Domain"
    result = subprocess.run(
        [
            'curl', '--socks5', '%s:%d' % (SOCKS_PROXY['host'], SOCKS_PROXY['port']),
            '-s', '-X', 'POST', 'http://whois.nic.ai/',
            '-d', 'Query=%s&QueryType=Domain' % domain,
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError('curl failed: ' + result.stderr)
    html = result.stdout
    if 'Domain not found' in html:
        save_result(target, record, domain, registered=False)
        return False
    elif 'Registry Domain ID' in html:
        soup = BeautifulSoup(html, 'lxml')
        raw_info = None
        tmp = soup.select('pre.whoisContent')
        if len(tmp) > 0:
            raw_info = tmp[0].text
        save_result(target, record, domain, registered=True, raw_info=raw_info)
        return True
    else:
        logger.warning(html)
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
    text = nic_client.whois_lookup(dict(), domain, 0)

    if 'Rate limit exceeded' in text.lower() or len(text) < len(domain):
        logger.warning('whois limit exceeded, received: ' + text)
        change_ip()
        return False

    registered = is_valid(tld, text)

    pos = text.find('Last update of whois database')
    if pos != -1:
        text = text[0:pos]

    save_result(target, record, domain, registered=registered, raw_info=text)


def query(domain, max_retries=3):
    domain = domain.lower()
    tld = domain[(domain.find('.') + 1):]
    target = tld + '_domains'
    record = get_record(target, domain)
    if should_skip(domain, record):
        logger.info(f'{domain} already exists, skip querying')
        return False

    for attempt in range(max_retries):
        try:
            logger.info('Querying ' + domain)
            if tld == 'ai':
                return query_ai_http(domain, target, record)
            else:
                return query_whois_socket(domain, tld, target, record)
        except OSError as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                logger.warning('Retrying %s in %ds due to: %s', domain, wait, e)
                time.sleep(wait)
            else:
                raise


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
        futures = [executor.submit(query, domain) for domain in domains]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error("Query failed: %s", e)


def main():
    global SOCKS_PROXY
    proxy_str = os.environ.get('SOCKS_PROXY', 'localhost:9050')
    proxy_parts = proxy_str.rsplit(':', 1)
    if len(proxy_parts) != 2:
        raise ValueError('SOCKS_PROXY must be in host:port format')
    SOCKS_PROXY = {'host': proxy_parts[0], 'port': int(proxy_parts[1])}

    if 'DOMAIN_DB_URI' not in os.environ:
        logger.info('You can specify database URI via the DOMAIN_DB_URI environment variable')

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


if __name__ == '__main__':
    main()
