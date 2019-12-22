#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import secrets
from difflib import SequenceMatcher
from http import cookiejar
from multiprocessing import Lock
from typing import Dict, Union, Tuple, Optional
from typing import cast
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
from yawast.shared.exec_timer import ExecutionTimer

YAWAST_UA = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"YAWAST/{get_version()}/PY Chrome/77.0.3865.65 Safari/537.36"
)

SERVICE_UA = f"YAWAST/{get_version()}/PY"
_lock = Lock()


# class to block setting cookies from server responses
class _BlockCookiesSet(cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


_requester = requests.Session()
_file_not_found_handling: Dict[str, Dict[str, Union[bool, Response]]] = {}


def init(proxy: str, cookie: str, header: str) -> None:
    global _requester, _file_not_found_handling

    _requester.cookies.set_policy(_BlockCookiesSet())
    _requester.verify = False
    _requester.mount(
        "http://",
        HTTPAdapter(
            max_retries=urllib3.Retry(total=3, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
            pool_block=True,
        ),
    )
    _requester.mount(
        "https://",
        HTTPAdapter(
            max_retries=urllib3.Retry(total=3, read=5, connect=5, backoff_factor=0.3),
            pool_maxsize=50,
            pool_block=True,
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
            cookies = cookie.split(";")
        else:
            cookies = [cookie]

        for current_cookie in cookies:
            if "=" in cookie:
                name = current_cookie.split("=", 1)[0]
                val = current_cookie.split("=", 1)[1]
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

    _file_not_found_handling = {}


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
        url, headers=headers, allow_redirects=allow_redirects, timeout=timeout
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
    res = _requester.options(url, headers=headers, timeout=timeout)

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
        url, headers=headers, allow_redirects=allow_redirects, timeout=timeout
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms "
        f"(Body: {len(res.content)})"
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
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms "
        f"(Body: {len(res.content)})"
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

    res = _requester.request(verb, url, headers=headers, timeout=timeout)

    output.debug(
        f"{res.request.method}: {url} - completed ({res.status_code}) in "
        f"{int(res.elapsed.total_seconds() * 1000)}ms "
        f"(Body: {len(res.content)})"
    )

    return res


def http_json(
    url, allow_redirects=True, timeout: Optional[int] = 30
) -> Tuple[Dict, int]:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    global _requester

    headers = {"User-Agent": SERVICE_UA}

    res = _requester.get(
        url, headers=headers, allow_redirects=allow_redirects, timeout=timeout
    )
    return res.json(), res.status_code


def http_file_exists(
    url: str, allow_redirects=True, timeout: Optional[int] = 30
) -> Tuple[bool, Response]:
    # first, check our 404 handling
    domain = utils.get_domain(url)
    _get_404_handling(domain, url)

    if _file_not_found_handling[domain]["file"]:
        if _file_not_found_handling[domain]["head"]:
            # we have good HEAD handling - we will start with head, as it's more efficient for us
            head = http_head(url, allow_redirects=allow_redirects, timeout=timeout)

            # check for ok, and for server-side errors
            if head.status_code == 200 or head.status_code >= 500:
                # file exists, grab it
                get = http_get(url, allow_redirects=allow_redirects, timeout=timeout)

                return True, get
            else:
                return False, head
        else:
            # head isn't handled properly, default to GET
            get = http_get(url, allow_redirects=allow_redirects, timeout=timeout)

            return get.status_code == 200, get
    else:
        # the server doesn't handle 404s properly - there are a few different flavors of this issue, each
        # different version requires a different approach
        file_res = cast(Response, _file_not_found_handling[domain]["file_res"])
        if file_res.status_code == 200:
            # in this case, everything gets a 200, even if it doesn't exist
            # to handle this, we need to look at the response, and see if we can work out if it's
            # a file not found error, or something else.
            get = http_get(url, allow_redirects=allow_redirects, timeout=timeout)

            if response_body_is_text(file_res):
                if response_body_is_text(get):
                    # in case the responses are the same, check that first, then move on to comparing
                    # this should be caught by the code below, but this is faster
                    if file_res.content == get.content:
                        return False, get

                    # both are text, so we need to compare to see how similar they are
                    with ExecutionTimer() as tm:
                        ratio = SequenceMatcher(None, file_res.text, get.text).ratio()

                    output.debug(
                        f"Fuzzy Matching used. Text from known 404 and '{get.url}' compared in {tm.to_ms()}ms"
                    )

                    # check to see if we have an alignment of less than 90% between the known 404, and this response
                    # if it's less than 90%, we will assume that the response is different, and we have a hit
                    # this is somewhat error prone, as it depends on details of how the application works, though
                    # most errors should be very similar, so the false positive rate should be low.
                    if ratio < 0.9:
                        output.debug(
                            f"Fuzzy Matching used. Text from known 404 and '{get.url}' have a "
                            f"similarity of {ratio} - assuming valid file."
                        )

                        return True, get
                    else:
                        return False, get
                else:
                    # if file_res is text, and this isn't, safe to call this a valid hit
                    return True, get
            else:
                # this is a case that makes no sense. who knows what's going on here.
                return file_res.content == get.content, get
        elif file_res.status_code in range(300, 399):
            # they are sending a redirect on file not found
            # we can't honor the allow_redirects flag, as we can't tell if it's a legit redirect, or an error
            # we should though get a 200 for valid hits
            get = http_get(url, allow_redirects=False, timeout=timeout)

            return get.status_code == 200, get
        elif file_res.status_code >= 400:
            # they are sending an error code that isn't 404 - in this case, we should still get a 200 on a valid hit
            get = http_get(url, allow_redirects=allow_redirects, timeout=timeout)

            return get.status_code == 200, get
        else:
            # shrug
            get = http_get(url, allow_redirects=allow_redirects, timeout=timeout)

            return get.status_code == 200, get


def http_build_raw_response(res: Response) -> str:
    if res.raw.version == 11:
        res_line = f"HTTP/1.1 {res.raw.status} {res.raw.reason}"
    else:
        res_line = f"HTTP/1.0 {res.raw.status} {res.raw.reason}"

    res_string = res_line + "\r\n"

    if res.raw._original_response is not None:
        res_string += "\r\n".join(
            str(res.raw._original_response.headers).splitlines(False)
        )
    else:
        res_string += "\r\n".join(f"{k}: {v}" for k, v in res.headers.items())

    try:
        if response_body_is_text(res):
            txt = res.text

            if txt != "":
                res_string += "\r\n\r\n"

                res_string += txt
        elif len(res.content) > 0:
            # the body is binary - no real value in keeping it
            res_string += "\r\n\r\n<BINARY DATA EXCLUDED>"
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
    domain = utils.get_domain(url)
    _get_404_handling(domain, url)

    return (
        _file_not_found_handling[domain]["file"],
        _file_not_found_handling[domain]["file_res"],
        _file_not_found_handling[domain]["path"],
        _file_not_found_handling[domain]["path_res"],
    )


def _get_404_handling(domain: str, url: str):
    with _lock:
        if domain not in _file_not_found_handling:
            _file_not_found_handling[domain] = {}

            target = utils.extract_url(url)

            rnd = secrets.token_hex(12)
            file_url = urljoin(target, f"{rnd}.html")
            path_url = urljoin(target, f"{rnd}/")

            file_res = http_get(file_url, False)
            path_res = http_get(path_url, False)

            _file_not_found_handling[domain]["file"] = file_res.status_code == 404
            _file_not_found_handling[domain]["file_res"] = file_res
            _file_not_found_handling[domain]["path"] = path_res.status_code == 404
            _file_not_found_handling[domain]["path_res"] = path_res

            # check to see if HEAD returns something reasonable
            head_res = http_head(file_url, False)

            _file_not_found_handling[domain]["head"] = head_res.status_code == 404
            _file_not_found_handling[domain]["head_res"] = head_res


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


def response_body_is_text(res: Response) -> bool:
    """
    Returns True if the body is HTML, or at least seems like text
    :param res:
    :return:
    """
    has_text = False

    if len(res.content) == 0:
        # don't bother with these, if the body is empty
        has_text = False
    elif "Content-Type" in res.headers and "text/html" in res.headers["Content-Type"]:
        # it's HTML, go
        has_text = True
    elif "Content-Type" not in res.headers:
        # this is something, but the server doesn't tell us what
        # so, we will check to see if if we can treat it like text
        if utils.is_printable_str(res.content):
            has_text = True

    return has_text


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
