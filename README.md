# Domain Crawler[![Build Status](https://travis-ci.org/soulmachine/domain-crawler.png)](https://travis-ci.org/soulmachine/domain-crawler)

## Introduction

This is a domain crawler that crawls whois information of domains.

## How to run

First, launch a Tor container,

```bash
docker run -d --name tor -p 9050:9050 -p 9051:9051 -p 8118:8118 soulmachine/tor
```

Second, launch a MongoDb container,

```bash
docker volume create mongodb-data
docker run --name mongodb -p 27017:27017 -v mongodb-data:/data/db -d mongo --serviceExecutor adaptive
```

At last, start the crawler,

```bash
python3 whois_crawler.py google-10000-english-usa-no-swears-short.txt ai
python3 whois_crawler.py google-10000-english-usa-no-swears-short.txt coin prefix com
```
