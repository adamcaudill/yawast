#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import re
from typing import Tuple, Union, List, cast
from urllib.parse import urljoin

from packaging import version
from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import version_checker, response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output


def identify(url: str) -> Tuple[Union[str, None], List[Result]]:
    results = []

    # find WordPress
    res, path = _identify_by_path(url, "")

    if path is None:
        res, path = _identify_by_path(url, "blog/")

    # check to see if we have a valid hit
    if path is not None:
        # we have a WordPress install, let's see if we can get a version
        body = res.text

        ver = "Unknown"
        # this works for modern versions
        m = re.search(r"login.min.css\?ver=\d+\.\d+\.?\d*", body)
        if m:
            ver = m.group(0).split("=")[1]
        else:
            # the current method doesn't work, fall back to an older method
            m = re.search(r"load-styles.php\?[\w,;=&%]+;ver=\d+\.\d+\.?\d*", body)
            if m:
                ver = m.group(0).split("=")[-1]

        # report that we found WordPress
        results.append(
            Result.from_evidence(
                Evidence.from_response(res, {"version": ver}),
                f"Found WordPress v{ver} at {path}",
                Vulnerabilities.APP_WORDPRESS_VERSION,
            )
        )

        # is this a current version?
        ver = cast(version.Version, version.parse(ver))
        curr_version = version_checker.get_latest_version("wordpress", ver)

        if curr_version is not None and curr_version > ver:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(
                        res,
                        {
                            "installed_version": str(ver),
                            "current_verison": str(curr_version),
                        },
                    ),
                    f"WordPress Outdated: {ver} - Current: {curr_version}",
                    Vulnerabilities.APP_WORDPRESS_OUTDATED,
                )
            )

        return path, results
    else:
        return None, []


def check_path_disclosure(wp_url: str) -> List[Result]:
    # this is a list of files that are known to throw a fatal error when accessed directly
    # this is from a manual review of all plugins with at least 1M installs
    urls = [
        "wp-content/plugins/hello.php",
        "wp-content/plugins/akismet/akismet.php",
        "wp-content/plugins/contact-form-7/includes/capabilities.php",
        "wp-content/plugins/wordpress-seo/admin/views/partial-alerts-errors.php",
        "wp-content/plugins/jetpack/load-jetpack.php",
        "wp-content/plugins/jetpack/uninstall.php",
        "wp-content/plugins/duplicate-post/duplicate-post-admin.php",
        "wp-content/plugins/wpforms-lite/includes/admin/class-welcome.php",
        "wp-content/plugins/wp-google-maps/base/includes/welcome.php",
        "wp-content/plugins/wp-super-cache/wp-cache.php",
        "wp-content/plugins/mailchimp-for-wp/integrations/wpforms/bootstrap.php",
        "wp-content/plugins/mailchimp-for-wp/integrations/bootstrap.php",
        "wp-content/plugins/regenerate-thumbnails/regenerate-thumbnails.php",
        "wp-content/plugins/advanced-custom-fields/includes/deprecated.php",
        "wp-content/plugins/redirection/redirection.php",
        "wp-content/plugins/wpforms-lite/includes/admin/importers/class-ninja-forms.php",
        "wp-content/plugins/ninja-forms/includes/deprecated.php",
        "wp-content/plugins/so-widgets-bundle/so-widgets-bundle.php",
        "wp-content/plugins/wp-fastest-cache/templates/preload.php",
        "wp-content/plugins/duplicate-page/duplicatepage.php",
        "wp-content/plugins/better-wp-security/better-wp-security.php",
        "wp-content/plugins/all-in-one-wp-security-and-firewall/other-includes/wp-security-unlock-request.php",
        "wp-content/plugins/related-posts/views/settings.php",
        "wp-content/plugins/wpcontentguard/views/settings.php",
        "wp-content/plugins/simple-social-icons/simple-social-icons.php",
    ]
    results: List[Result] = []

    for url in urls:
        target = urljoin(wp_url, url)

        head = network.http_head(target, False)
        if head.status_code != 404:
            resp = network.http_get(target, False)
            if resp.status_code < 300 or resp.status_code >= 500:
                # we have some kind of response that could be useful
                if "<b>Fatal error</b>:" in resp.text:
                    # we have an error
                    pattern = r"<b>((\/|[A-Z]:\\).*.php)<\/b>"
                    if re.search(pattern, resp.text):
                        try:
                            path = re.findall(pattern, resp.text)[0][0]
                            results.append(
                                Result.from_evidence(
                                    Evidence.from_response(resp, {"path": path}),
                                    f"WordPress File Path Disclosure: {target} ({path})",
                                    Vulnerabilities.APP_WORDPRESS_PATH_DISCLOSURE,
                                )
                            )
                        except Exception:
                            output.debug_exception()

            results += response_scanner.check_response(target, resp)

    return results


def check_json_user_enum(url: str) -> List[Result]:
    results = []
    target = urljoin(url, "wp-json/wp/v2/users")

    res = network.http_get(target, False)
    body = res.text

    if res.status_code < 300 and "slug" in body:
        data = res.json()

        # log the enum finding
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"WordPress WP-JSON User Enumeration at {target}",
                Vulnerabilities.APP_WORDPRESS_USER_ENUM_API,
            )
        )

        # log the individual users
        for user in data:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(
                        res,
                        {
                            "user_id": user["id"],
                            "user_slug": user["slug"],
                            "user_name": user["name"],
                        },
                    ),
                    f"ID: {user['id']}\tUser Slug: '{user['slug']}'\t\tUser Name: '{user['name']}'",
                    Vulnerabilities.APP_WORDPRESS_USER_FOUND,
                )
            )

    return results


def _identify_by_path(url: str, path: str) -> Tuple[Response, Union[str, None]]:
    target = urljoin(url, f"{path}wp-login.php")

    res = network.http_get(target, False)
    body = res.text

    if res.status_code == 200 and "Powered by WordPress" in body:
        return res, urljoin(url, path)
    else:
        return res, None
