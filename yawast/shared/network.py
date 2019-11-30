#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import secrets
from http import cookiejar
from typing import Dict, Union, Tuple, Optional
from urllib.parse import urlparse, urljoin
from urllib.parse import urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.models import Response, Request, PreparedRequest
from requests_mock.request import _RequestObjectProxy
from validator_collection import checkers

from yawast._version import get_version
from yawast.reporting import reporter
from yawast.shared import output, utils

YAWAST_UA = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"YAWAST/{get_version()}/PY Chrome/77.0.3865.65 Safari/537.36"
)

SERVICE_UA = f"YAWAST/{get_version()}/PY"


# class to block setting cookies from server responses
class _BlockCookiesSet(cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


_requester = requests.Session()


def init(proxy: str, cookie: str, header: str) -> None:
    global _requester

    _requester.cookies.set_policy(_BlockCookiesSet())
    _requester.mount(
        "http://",
        HTTPAdapter(
            max_retries=urllib3.Retry(total=3, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
        ),
    )
    _requester.mount(
        "https://",
        HTTPAdapter(
            max_retries=urllib3.Retry(total=3, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
        ),
    )

    if proxy is not None and len(proxy) > 0:
        # we have a proxy, set it
        if not proxy.startswith("http") and "://" not in proxy:
            proxy = f"http://{proxy}"

        if proxy.startswith("http"):
            proxies = {"http": proxy, "https": proxy}

            _requester.proxies.update(proxies)
        else:
            output.error(
                f"Invalid proxy server specified ({proxy}) - only HTTP proxy servers are supported. Proxy ignored."
            )

    if cookie is not None and len(cookie) > 0:
        if ";" in cookie:
            current_cookie = cookie.split(";")
        else:
            current_cookie = cookie
         
        for i in current_cookie:
            if "=" in cookie:
                name = i.split("=", 1)[0]
                val = i.split("=", 1)[1]
                c = requests.cookies.create_cookie(name=name, value=val)

                _requester.cookies.set_cookie(c)
            else:
                output.error(
                    f"Invalid cookie specified ({cookie}) - cookie must be in NAME=VALUE format. Ignored."
                    )

    if header is not None and len(header) > 0:
        if "=" in header:
            name = header.split("=", 1)[0]
            val = header.split("=", 1)[1]
            _requester.headers.update({name: val})
        elif ": " in header:
            # in case they use the wire format - not officially supported, but, meh
            name = header.split(": ", 1)[0]
            val = header.split(": ", 1)[1]
            _requester.headers.update({name: val})
        else:
            output.error(
                f"Invalid header specified ({header}) - header must be in NAME=VALUE format. Ignored."
            )


def reset():
    global _requester

    _requester = requests.Session()


def http_head(
    url: str, allow_redirects: Optional[bool] = True, timeout: Optional[int] = 30
) -> Response:
    global _requester

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"User-Agent": YAWAST_UA}
    res = _requester.head(
        url,
        headers=headers,
        verify=False,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_options(url: str, timeout: Optional[int] = 30) -> Response:
    global _requester

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"User-Agent": YAWAST_UA}
    res = _requester.options(url, headers=headers, verify=False, timeout=timeout)

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_get(
    url: str,
    allow_redirects: Optional[bool] = True,
    additional_headers: Union[None, Dict] = None,
    timeout: Optional[int] = 30,
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.get(
        url,
        headers=headers,
        verify=False,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_put(
    url: str,
    data: str,
    allow_redirects=True,
    additional_headers: Union[None, Dict] = None,
    timeout: Optional[int] = 30,
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.put(
        url,
        data=data,
        headers=headers,
        verify=False,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_custom(
    verb: str,
    url: str,
    additional_headers: Union[None, Dict] = None,
    timeout: Optional[int] = 30,
) -> Response:

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": YAWAST_UA}

    if additional_headers is not None:
        headers = {**headers, **additional_headers}

    res = _requester.request(verb, url, headers=headers, verify=False, timeout=timeout)

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms."
    )

    return res


def http_json(
    url, allow_redirects=True, timeout: Optional[int] = 30
) -> Tuple[Dict, int]:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": SERVICE_UA}

    res = _requester.get(
        url,
        headers=headers,
        verify=False,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )
    return res.json(), res.status_code


def http_build_raw_response(res: Response) -> str:
    if res.raw.version == 11:
        res_line = f"HTTP/1.1 {res.raw.status} {res.raw.reason}"
    else:
        res_line = f"HTTP/1.0 {res.raw.status} {res.raw.reason}"

    res_string = res_line + "\r\n"

    res_string += "\r\n".join(f"{k}: {v}" for k, v in res.headers.items())

    try:
        txt = res.text

        if txt != "":
            res_string += "\r\n\r\n"

            res_string += txt
    except Exception:
        output.debug_exception()

    return res_string


def http_build_raw_request(
    req: Union[Request, PreparedRequest, _RequestObjectProxy]
) -> str:
    if type(req) is _RequestObjectProxy:
        req = req._request

    headers = "\r\n".join(f"{k}: {v}" for k, v in req.headers.items())

    body = ""
    if req.body is not None:
        body = req.body

    return f"{req.method} {req.url}\r\n{headers}\r\n\r\n{body}"


def check_404_response(url: str) -> Tuple[bool, Response, bool, Response]:
    rnd = secrets.token_hex(12)
    file_url = urljoin(url, f"{rnd}.html")
    path_url = urljoin(url, f"{rnd}/")

    file_res = http_get(file_url, False)
    path_res = http_get(path_url, False)

    return file_res.status_code == 404, file_res, path_res.status_code == 404, path_res


def check_ssl_redirect(url):
    parsed = urlparse(url)

    if parsed.scheme == "https":
        return url

    req = http_head(url, False)

    # make sure we received a redirect response
    if req.status_code >= 300 & req.status_code < 400:
        location = req.headers.get("location")

        if location is None:
            return url

        try:
            parsed_location = urlparse(location)

            # this is a special case to handle servers that redirect to a path, and then to HTTPS
            if parsed_location.netloc == "" and parsed_location.path != "":
                parsed_location = parsed._replace(path=parsed_location.path)
                parsed_location = urlparse(
                    check_ssl_redirect(urlunparse(parsed_location))
                )

            if parsed_location.scheme == "https":
                parsed = parsed._replace(scheme=parsed_location.scheme)

                return urlunparse(parsed)
        except Exception:
            return url

    return url


def check_www_redirect(url):
    parsed = urlparse(url)

    req = http_head(url, False)

    # make sure we received a redirect response
    if req.status_code >= 300 & req.status_code < 400:
        location = req.headers.get("location")

        if location is None:
            return url

        if str(location).startswith("/"):
            return url

        try:
            parsed_location = urlparse(location)
            location_domain = utils.get_domain(parsed_location.netloc)
            domain = utils.get_domain(parsed.netloc)

            if (
                domain.startswith("www")
                and (not location_domain.startswith("www"))
                and location_domain in domain
            ):
                parsed_location = parsed._replace(netloc=parsed_location.netloc)

                return urlunparse(parsed_location)
            elif (
                (not domain.startswith("www"))
                and location_domain.startswith("www")
                and domain in location_domain
            ):
                parsed_location = parsed._replace(netloc=parsed_location.netloc)

                return urlunparse(parsed_location)
        except ValueError:
            return url
    else:
        return url


def check_ipv4_connection() -> str:
    prefix = "IPv4 -> Internet:"
    url = "https://ipv4.icanhazip.com/"

    try:
        res = _check_connection(url)

        if not checkers.is_ipv4(res):
            res = "(Unavailable)"
    except Exception:
        res = "(Unavailable)"

    reporter.register_info("ipv4", res)

    return f"{prefix} {res}"


def check_ipv6_connection() -> str:
    prefix = "IPv6 -> Internet:"
    url = "https://ipv6.icanhazip.com/"

    try:
        res = _check_connection(url)

        if not checkers.is_ipv6(res):
            res = "(Unavailable)"
    except Exception:
        res = "(Unavailable)"

    reporter.register_info("ipv6", res)

    return f"{prefix} {res}"


def _check_connection(url: str) -> str:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    result = "Connection Failed"

    try:
        headers = {"User-Agent": SERVICE_UA}

        res = requests.get(url, headers=headers, verify=False)

        result = res.text.strip()
    except Exception:
        output.debug_exception()

    return result
