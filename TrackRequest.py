# -*- coding=utf-8 -*-
import requests
import logging
import sys


class TrackRequest:
    def __init__(self, url):
        self.url = url
        self.header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'}
        self.timeout = 3

    def check_url(self):
        try:
            req = requests.get(self.url, headers=self.header, timeout=self.timeout)
            req.raise_for_status()
        except requests.RequestException as e:
            logging.error('[-] {} is error...'.format(self.url))
            sys.exit(1)

    def check_url_info(self):
        try:
            req = requests.get(self.url, headers=self.header, timeout=self.timeout)
            req.raise_for_status()
            if req.status_code == 200:
                logging.info('[+] {} is exist...'.format(self.url))
                return self.url
        except requests.RequestException as e:
            return 0
