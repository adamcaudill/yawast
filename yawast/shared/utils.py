#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import ipaddress
import re
import sys
import threading
import time
from urllib.parse import urlparse
from urllib.parse import urlunparse

from validator_collection import checkers

from yawast.shared import output
from yawast.shared.exec_timer import ExecutionTimer

INPUT_LOCK = threading.Lock()
ANSI_STRIP = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def is_url(url):
    try:
        url = extract_url(url)

        if checkers.is_url(url, allow_special_ips=True):
            parsed = urlparse(url)

            if parsed.scheme == "http" or parsed.scheme == "https":
                # make sure the data we have is at least valid-ish
                return all(
                    [
                        parsed.scheme,
                        parsed.netloc,
                        (parsed.port is None or parsed.port > 0),
                    ]
                )
            else:
                return False
        else:
            return False
    except ValueError:
        return False


def is_ip(val):
    # strip any wrapping for an IPv6 used in a URL
    val = str(val).lstrip("[").rstrip("]")

    return checkers.is_ip_address(val)


def is_private_ip(val):
    # strip any wrapping for an IPv6 used in a URL
    val = str(val).lstrip("[").rstrip("]")

    return ipaddress.ip_address(str(val)).is_private


def get_domain(val: str) -> str:
    val = str(val)
    val = urlparse(extract_url(val)).netloc

    # strip any credentials
    if "@" in val:
        val = val.rpartition("@")[-1]

    # strip any port number
    if ":" in val:
        # we check for an ending ']' because of IPv6
        if not val.endswith("]"):
            val = val.rpartition(":")[0]

    return val


def is_printable_str(b: bytes) -> bool:
    decoders = ["utf_8", "latin_1", "cp1251"]
    printable = False
    good_decoder = None

    with ExecutionTimer() as timer:
        for decoder in decoders:
            s = b.decode(decoder, "backslashreplace")

            if not any(
                repr(ch).startswith("'\\x") or repr(ch).startswith("'\\u") for ch in s
            ):
                printable = True
                good_decoder = decoder

                break

    if good_decoder is not None:
        output.debug(f"Decoded string as {good_decoder} in {timer.to_ms()}ms")
    else:
        output.debug(f"Failed to decode string in {timer.to_ms()}ms")

    return printable


def strip_ansi_str(val: str) -> str:
    return ANSI_STRIP.sub("", val)


def get_port(url: str) -> int:
    parsed = urlparse(url)
    url = parsed.netloc

    if parsed.port is not None:
        return int(parsed.port)

    # strip any credentials
    if "@" in url:
        url = url.rpartition("@")[-1]

    # get any port number
    if ":" in url:
        # we check for an ending ']' because of IPv6
        if not url.endswith("]"):
            return int(url.rpartition(":")[1])

    if parsed.scheme == "https":
        return 443
    elif parsed.scheme == "http":
        return 80


def extract_url(url):
    # check for extra slashes in the scheme
    if re.match(r"^[a-z]{2,8}:///+", url, re.IGNORECASE):
        url = re.sub(r":///+", "://", url, 1)

    # check to see if we already have something that looks like a valid scheme
    # we'll only process the cleanup if we don't match
    if not re.match(r"^[a-z]{2,8}://", url, re.IGNORECASE):
        # fix a missing colon
        if url.lower().startswith("http//") or url.lower().startswith("https//"):
            url = url.replace("//", "://", 1)

        # fix URLs that a missing a slash after the scheme
        if re.match(r"^http[s]?:/[^/]", url, re.IGNORECASE):
            url = url.replace(":/", "://", 1)

        # this might be buggy - actually, I know it is...
        # if the URL is malformed, this can lead to some very wrong things
        if not (
            url.lower().startswith("http://") or url.lower().startswith("https://")
        ):
            url = "http://" + url

    # parse the URL so that we can get into the more detailed cleanup
    parsed = urlparse(url)

    # force name to lower, if it isn't
    if parsed.netloc != parsed.netloc.lower():
        parsed = parsed._replace(netloc=parsed.netloc.lower())

    # make sure we have something set for the path
    if parsed.path == "":
        parsed = parsed._replace(path="/")

    # make sure that we are looking at root (most common) or a folder, not a file
    if not parsed.path.endswith("/"):
        # this isn't a great solution, but for now...
        # strip everything after the last slash
        new_path = parsed.path.rsplit("/", 1)[0] + "/"
        parsed = parsed._replace(path=new_path)

    # remove any query strings. not something we can work with
    if not parsed.query == "":
        parsed = parsed._replace(query="")

    # remove any fragment strings. not something we can work with
    if not parsed.fragment == "":
        parsed = parsed._replace(fragment="")

    # remove any parameters. not something we can work with
    if not parsed.params == "":
        parsed = parsed._replace(params="")

    return urlunparse(parsed)


def exit_message(message: str):
    print(message, file=sys.stderr)
    sys.exit(-1)


def prompt(msg: str) -> str:
    ret = ""

    if sys.stdout.isatty():
        INPUT_LOCK.acquire()
        sys.stdin.flush()
        time.sleep(0.1)
        ret = input(msg)
        INPUT_LOCK.release()

    return ret
