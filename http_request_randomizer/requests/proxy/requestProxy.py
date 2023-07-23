import logging
import os
import random
import sys
import time

import requests
from requests.exceptions import ChunkedEncodingError
from requests.exceptions import TooManyRedirects
from requests.exceptions import ConnectionError
from requests.exceptions import ReadTimeout

from http_request_randomizer.requests.proxy.ProxyObject import Protocol
from http_request_randomizer.requests.errors.ProxyListException import ProxyListException
from http_request_randomizer.requests.parsers.FreeProxyParser import FreeProxyParser
from http_request_randomizer.requests.parsers.ProxyForEuParser import ProxyForEuParser
from http_request_randomizer.requests.parsers.RebroWeeblyParser import RebroWeeblyParser
from http_request_randomizer.requests.parsers.PremProxyParser import PremProxyParser
from http_request_randomizer.requests.parsers.SslProxyParser import SslProxyParser
from http_request_randomizer.requests.useragent.userAgent import UserAgentManager

from fp.fp import FreeProxy, FreeProxyException

__author__ = 'pgaref'
sys.path.insert(0, os.path.abspath('../../../../'))

# Push back requests library to at least warnings
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-6s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)

class RequestInstance():
    def __init__(self, method, headers, data, params, req_timeout, proxy ):
        self.method = method
        self.headers = headers
        self.data = data
        self.params = params
        self.req_timeout = req_timeout
        self.proxy = proxy
        
    def performRequest(self, url):
        return requests.request(self.method, url, headers=self.headers, data=self.data, params=self.params, timeout=self.req_timeout,
                proxies={
                    "http": "http://{0}".format(self.proxy),
                    "https": "https://{0}".format(self.proxy)
                })

class RequestProxy:
    def __init__(self, web_proxy_list=[], sustain=False, timeout=5, protocol=Protocol.HTTP, log_level=0):
        self.logger = logging.getLogger()
        self.logger.addHandler(handler)
        self.logger.setLevel(log_level)
        self.userAgent = UserAgentManager(file=os.path.join(os.path.dirname(__file__), '../data/user_agents.txt'))
        self.sustain = sustain
        self.proxy_provider = FreeProxy()

        self.proxy_list = self.proxy_provider.get_proxy_list(True)
        self.current_proxy = self.randomize_proxy()

    def set_logger_level(self, level):
        self.logger.setLevel(level)

    def get_proxy_list(self):
        return self.proxy_list

    def generate_random_request_headers(self):
        headers = {
            "Connection": "close",  # another way to cover tracks
            "User-Agent": self.userAgent.get_random_user_agent()
        }  # select a random user agent
        return headers

    def randomize_proxy(self):
                
        if len(self.proxy_list) == 0:
            raise ProxyListException("list is empty")
        
        rand_proxy = random.choice(self.proxy_list)
        while not rand_proxy:
            rand_proxy = random.choice(self.proxy_list)
        self.current_proxy = rand_proxy
        return rand_proxy

    #####
    # Proxy format:
    # http://<USERNAME>:<PASSWORD>@<IP-ADDR>:<PORT>
    #####
    

    
    def generate_proxied_request(self, url, method="GET", params={}, data={}, headers={}, req_timeout=30):
        try:
            random.shuffle(self.proxy_list)
            # req_headers = dict(params.items() + self.generate_random_request_headers().items())

            req_headers = dict(params.items())
            req_headers_random = dict(self.generate_random_request_headers().items())
            req_headers.update(req_headers_random)

            if not self.sustain:
                self.randomize_proxy()

            headers.update(req_headers)

            self.logger.debug("Using headers: {0}".format(str(headers)))
            self.logger.debug("Using proxy: {0}".format(str(self.current_proxy)))
            
            self.current_request_instance = RequestInstance(method, headers, data, params, req_timeout, self.current_proxy)
            request = self.current_request_instance.performRequest(url)
            # request = requests.request(method, url, headers=headers, data=data, params=params, timeout=req_timeout,
            #         proxies={
            #             "http": "http://{0}".format(self.current_proxy),
            #             "https": "https://{0}".format(self.current_proxy)
            #         })
            # Avoid HTTP request errors
            if request.status_code == 409:
                raise ConnectionError("HTTP Response [409] - Possible Cloudflare DNS resolution error")
            elif request.status_code == 403:
                raise ConnectionError("HTTP Response [403] - Permission denied error")
            elif request.status_code == 503:
                raise ConnectionError("HTTP Response [503] - Service unavailable error")
            self.logger.info('RR Status {}'.format(request.status_code))
            
            
            
            return request
        
        except ConnectionError:
            try:
                self.proxy_list.remove(self.current_proxy)
            except ValueError:
                pass
            self.logger.debug("Proxy unreachable - Removed Straggling proxy: {0} PL Size = {1}".format(
                self.current_proxy, len(self.proxy_list)))
            self.randomize_proxy()
        except ReadTimeout:
            try:
                self.proxy_list.remove(self.current_proxy)
            except ValueError:
                pass
            self.logger.debug("Read timed out - Removed Straggling proxy: {0} PL Size = {1}".format(
                self.current_proxy, len(self.proxy_list)))
            self.randomize_proxy()
        except ChunkedEncodingError:
            try:
                self.proxy_list.remove(self.current_proxy)
            except ValueError:
                pass
            self.logger.debug("Wrong server chunked encoding - Removed Straggling proxy: {0} PL Size = {1}".format(
                self.current_proxy, len(self.proxy_list)))
            self.randomize_proxy()
        except TooManyRedirects:
            try:
                self.proxy_list.remove(self.current_proxy)
            except ValueError:
                pass
            self.logger.debug("Too many redirects - Removed Straggling proxy: {0} PL Size = {1}".format(
                self.current_proxy, len(self.proxy_list)))
            self.randomize_proxy()


hard_url = 'https://www.cardmarket.com/en/Magic/Products/Singles/Modern-Horizons-2/Academy-Manufactor?language=1&minCondition=2'



if __name__ == '__main__':

    start = time.time()
    req_proxy = RequestProxy()
    print("Initialization took: {0} sec".format((time.time() - start)))
    print("Size: {0}".format(len(req_proxy.get_proxy_list())))
    # print("ALL = {0} ".format(list(map(lambda x: x.get_address(), req_proxy.get_proxy_list()))))

    test_url = 'http://ipv4.icanhazip.com'

    while True:
        start = time.time()
        request = req_proxy.generate_proxied_request(test_url, req_timeout=4.0)
        print("Proxied Request Took: {0} sec => Status: {1}".format((time.time() - start), request.__str__()))
        if request is not None:
            print("\t Response: ip={0}".format(u''.join(request.text).encode('utf-8')))
            
            print("Success now trying this ip with hard url.")
            
            mkm_response = req_proxy.current_request_instance.performRequest(hard_url)
            
            if mkm_response is not None:
                if mkm_response.status_code == 200:
                    print("MKM - SUCCESS")

            
            
            
            
