#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from argparse import Namespace
from urllib.parse import ParseResult, urlparse, urlunparse

from yawast.shared import utils


class Session:
    args: Namespace
    url: str = ""
    url_parsed: ParseResult
    domain: str = ""
    supports_https: bool = False
    redirects_https: bool = False
    supports_http: bool = False

    def __init__(self, args: Namespace, url: str):
        self.args = args
        self.url = url
        self.url_parsed = urlparse(url)
        self.domain = utils.get_domain(self.url_parsed.netloc)

    def update_scheme(self, scheme: str):
        # this is the documented way to do this, even though it's a private member
        self.url_parsed = self.url_parsed._replace(scheme=scheme)
        self.url = urlunparse(self.url_parsed)

    def update_url(self, url: str):
        self.url = url
        self.url_parsed = urlparse(url)
        self.domain = utils.get_domain(self.url_parsed.netloc)

    def get_http_url(self):
        http_parsed = self.url_parsed._replace(scheme="http")
        http_url = urlunparse(http_parsed)

        return http_url
