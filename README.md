# Domain Crawler[![Build Status](https://travis-ci.org/soulmachine/domain-crawler.png)](https://travis-ci.org/soulmachine/domain-crawler)

## Introduction

This is a domain crawler that crawls whois information of domains.

## Building

Assuming you already have [SBT] [sbt] installed:

    $ git clone git://github.com/soulmachine/domain-crawler.git
    $ cd domain-crawler
    $ sbt assembly

The 'fat jar' is now available as:

    target/scala-2.11/spark-example-project-1.0.jar

## Unit testing

The `assembly` command above runs the test suite - but you can also run this manually with:

    $ sbt test
