#!/usr/bin/env python3
from datetime import datetime
import whois
import pymongo
import sys
import threading
import queue

mongo_client = pymongo.MongoClient('localhost', 27017)
db = mongo_client.domain

NUM_THREADS = 2
q = queue.Queue()


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
        if (datetime.now() - record['updatedAt']).days < 30:  # last query was within 30 days
            return False
    # doesn't exists or has expired
    try:
        print('Querying ' + domain)
        info = whois.whois(domain)
        info['_id'] = info.domain
        info['registered'] = True
        info['createdAt'] = datetime.now()
        info['updatedAt'] = datetime.now()
        db.domains.insert(info)
        return True
    except whois.parser.PywhoisError:  # domain not registered
        if record is None:  # insert
            db.domains.insert({'_id': domain, 'registered': False, 'createdAt': datetime.now(), 'updatedAt': datetime.now()})
        else:  # update
            db.domains.update({'_id': domain}, {'$set': {'registered': False, 'updatedAt': datetime.now()}})
        return False
    except pymongo.errors.DuplicateKeyError:  # update
        if (datetime.now() - record['updatedAt']).days > 30:  # last query was within 30 days
            db.domains.delete_one({'_id': domain})
            db.domains.insert(info)
            return True
        else:
            db.domains.update({'_id': domain}, {'$set': {'updatedAt': datetime.now()}})
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
