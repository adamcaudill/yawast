#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import os
import time
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from multiprocessing import Manager, active_children
from multiprocessing.dummy import Pool
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import pkg_resources
from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output

_files: List[str] = []
_depth = 0


def find_files(url: str, path: Optional[str] = None) -> Tuple[List[str], List[Result]]:
    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename(
            "yawast", "resources/common_file.txt"
        )
    else:
        file_path = path

    return _find_files(url, file_path)


def find_directories(
    url: str, follow_redirections, recursive: bool, path: Optional[str] = None
) -> Tuple[List[str], List[Result]]:
    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename(
            "yawast", "resources/common_dir.txt"
        )
    else:
        file_path = path

    return _find_files(url, file_path, follow_redirections, True, recursive)


def find_backups(links: List[str]) -> Tuple[List[str], List[Result]]:
    new_links: List[str] = []
    results: List[Result] = []
    process_queue: List[str] = []

    def _extract_name(url: str) -> str:
        try:
            u = urlparse(url)
            return os.path.basename(u.path)
        except Exception:
            return ""

    def _get_resp(url: str) -> Tuple[bool, Response]:
        return network.http_file_exists(url, False)

    def _process(url: str, result: Tuple[bool, Response]):
        nonlocal results, new_links

        found, res = result

        if found:
            # we found something!
            new_links.append(url)

            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Found backup file: {url}",
                    Vulnerabilities.HTTP_BACKUP_FILE,
                )
            )

        results += response_scanner.check_response(target, res)

    extensions = [
        "~",
        ".bak",
        ".back",
        ".backup",
        ".1",
        ".old",
        ".orig",
        ".gz",
        ".tar.gz",
        ".tmp",
        ".swp",
    ]
    compressed = [".zip", ".tar.gz", ".gz", ".7z", ".tgz", ".rar", ".tar"]

    for link in links:
        # clean link of any junk
        parsed = urlparse(link)
        link = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # check for add-on extensions
        if not link.endswith("/"):
            if "." in _extract_name(link):
                for ext in extensions:
                    # add-on extension
                    target = f"{link}{ext}"
                    if target not in process_queue:
                        process_queue.append(target)

                    # replacement extension
                    target = f"{link[: link.rfind('.')]}{ext}"
                    if target not in process_queue and target != link:
                        process_queue.append(target)

        # checked for compressed directories
        dir_url = link[: link.rfind("/")]
        parsed_url = urlparse(dir_url)
        if len(parsed_url.path) > 0:
            # make sure we aren't at the root
            for cmp in compressed:
                target = f"{dir_url}{cmp}"

                if target not in process_queue:
                    process_queue.append(target)

    with ThreadPoolExecutor() as executor:
        f = {executor.submit(_get_resp, url): url for url in process_queue}
        for future in as_completed(f):
            url = f[future]
            resp = future.result()
            _process(url, resp)

    return new_links, results


def find_ds_store(links: List[str]) -> List[Result]:
    results = []
    queue = []

    def _get_resp(url: str) -> Tuple[bool, Response]:
        return network.http_file_exists(url, False)

    def _process(url: str, result: Tuple[bool, Response]):
        nonlocal results

        found, res = result

        if found and res.content.startswith(b"\0\0\0\1Bud1\0"):
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f".DS_Store File Found: {url}",
                    Vulnerabilities.HTTP_DS_STORE_FILE,
                )
            )

    for link in links:
        if link.endswith("/"):
            turl = urljoin(link, ".DS_Store")

            queue.append(turl)

    with ThreadPoolExecutor() as executor:
        f = {executor.submit(_get_resp, url): url for url in queue}
        for future in as_completed(f):
            url = f[future]
            resp = future.result()
            _process(url, resp)

    return results


def reset():
    global _files, _depth

    _files = []
    _depth = 0


def _find_files(
    url: str,
    path: str,
    follow_redirections: Optional[bool] = False,
    is_dir: Optional[bool] = False,
    recursive: Optional[bool] = False,
) -> Tuple[List[str], List[Result]]:
    global _files, _depth

    # increment the depth counter, if this is greater than 1, this is a recursive call
    _depth += 1

    files: List[str] = []
    results: List[Result] = []
    workers = []

    # create processing pool
    pool = Pool(os.cpu_count())
    mgr = Manager()
    queue = mgr.Queue()

    try:
        with open(path) as file:
            urls = []

            for line in file:
                # if we are looking for directories, add the trailing slash
                trailer = "/" if is_dir else ""

                target_url = urljoin(url, f"{line.strip()}{trailer}")

                if recursive:
                    # skip it we've already tried it
                    # we only check if the recursive option is enabled, as it's the only way this should happen
                    if target_url not in _files:
                        urls.append(target_url)
                else:
                    urls.append(target_url)

                if len(urls) > 100:
                    asy = pool.apply_async(
                        _check_url, (urls[:], queue, follow_redirections, recursive)
                    )

                    # work around a Python bug - this sets a long timeout
                    # this triggers signals to be properly processed
                    # see https://stackoverflow.com/a/1408476
                    asy.get(timeout=999999)

                    workers.append(asy)

                    urls = []

        # take care of any urls that didn't make it in (if the remainder is < 100, the loop will end before being queued
        pool.apply_async(_check_url, (urls[:], queue, follow_redirections, recursive))

        pool.close()

        while True:
            if all(r.ready() for r in workers):
                break

            time.sleep(1)

        while not queue.empty():
            fls, res = queue.get()

            if len(fls) > 0:
                for fl in fls:
                    if fl not in files:
                        files.append(fl)
            if len(res) > 0:
                for re in res:
                    if re not in results:
                        results.append(re)

    except KeyboardInterrupt:
        active_children()

        pool.terminate()
        pool.join()

        raise
    except Exception:
        output.debug_exception()

        raise

    _depth -= 1
    if _depth == 0:
        # if there are no other iterations running, clean up
        _files = []

    return files, results


def _check_url(urls: List[str], queue, follow_redirections, recursive) -> None:
    files: List[str] = []
    results: List[Result] = []

    for url in urls:
        try:
            found, res = network.http_file_exists(url, False)

            if res.status_code < 300:
                # run a scan on the full result, so we can ensure that we get any issues
                results += response_scanner.check_response(url, res)

                files.append(url)

                if recursive:
                    fl, re = find_directories(url, follow_redirections, recursive)

                    files.extend(fl)
                    results.extend(re)
            elif res.status_code < 400 and follow_redirections:
                if "Location" in res.headers:
                    _check_url(
                        [res.headers["Location"]], queue, follow_redirections, recursive
                    )
        except Exception as error:
            output.debug(f"Error checking URL ({url}): {str(error)}")

    queue.put((files, results))
