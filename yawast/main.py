#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import gc
import locale
import platform
import signal
import ssl
import sys
import threading
import time
import warnings
from datetime import datetime
from multiprocessing import current_process, active_children
from typing import cast

import psutil
from colorama import Fore
from packaging import version

from yawast import command_line
from yawast._version import get_version
from yawast.external.get_char import getchar
from yawast.external.memory_size import Size
from yawast.external.spinner import Spinner
from yawast.reporting import reporter
from yawast.shared import output, network, utils

_start_time = datetime.now()
_monitor = None
_has_shutdown = False


def main():
    global _start_time, _monitor

    signal.signal(signal.SIGINT, signal_handler)

    warnings.simplefilter("ignore")

    try:
        if str(sys.stdout.encoding).lower() != "utf-8":
            print(f"Output encoding is {sys.stdout.encoding}: changing to UTF-8")

            sys.stdout.reconfigure(encoding="utf-8")
    except Exception as error:
        print(f"Unable to set UTF-8 encoding: {str(error)}")

    parser = command_line.build_parser()
    args, urls = parser.parse_known_args()

    # setup the output system
    output.setup(args.debug, args.nocolors, args.nowrap)
    output.debug("Starting application...")

    proxy = args.proxy if "proxy" in args else None
    cookie = args.cookie if "cookie" in args else None
    header = args.header if "header" in args else None
    network.init(proxy, cookie, header)

    # if we made it this far, it means that the parsing worked.
    # version doesn't require any URLs, so it gets special handing
    if args.command != "version":
        urls = command_line.process_urls(urls)
    else:
        urls = []

    # we are good to keep going
    print_header()

    if args.output is not None:
        reporter.init(args.output)
        _set_basic_info()

        print(f"Saving output to '{reporter.get_output_file()}'")
        print()

    try:
        with _KeyMonitor():
            with _ProcessMonitor() as pm:
                _monitor = pm

                args.func(args, urls)
    except KeyboardInterrupt:
        output.empty()
        output.error("Scan cancelled by user.")
    finally:
        _shutdown()


def print_header():
    start_time = time.strftime("%Y-%m-%d %H:%M:%S %Z (%z)", time.localtime())

    vm = psutil.virtual_memory()
    mem_total = "{0:cM}".format(Size(vm.total))
    mem_avail = "{0:cM}".format(Size(vm.available))

    cpu_freq = psutil.cpu_freq()
    cpu_max = int(cpu_freq.max)
    if cpu_max == 0:
        # in this case, we don't have a real max, so go with current
        cpu_max = int(cpu_freq.current)

    print(r" .-.          .-                           ")
    print(r"  \ \        / /                       _   ")
    print(r"   \ \      / /                       | |  ")
    print(r"    \ \    / /  __ ___      ____ _ ___| |_ ")
    print(r"     \ \  / /  / _` \ \ /\ / / _` / __| __|")
    print(r"      \ `  /  | (_| |\ V  V / (_| \__ \ |_ ")
    print(r"       \  /    \__,_| \_/\_/ \__,_|___/\__|")
    print(r"       / /                                 ")
    print(r"   |`-' /     ...where a pentest starts    ")
    print(r"    '..'                                   ")
    print()
    print(f"The YAWAST Antecedent Web Application Security Toolkit (v{get_version()})")
    print(
        " Copyright (c) 2013-2019 Adam Caudill <adam@adamcaudill.com> and Contributors"
    )
    print(" Support & Documentation: https://yawast.org")
    print(" News & Updates: https://twitter.com/yawast")
    print(
        f" Python {''.join(sys.version.splitlines())} ({platform.python_implementation()})"
    )
    print(f" {ssl.OPENSSL_VERSION}")
    print(f" Platform: {platform.platform()} ({_get_locale()} / {sys.stdout.encoding})")
    print(
        f" CPU(s): {psutil.cpu_count()}@{cpu_max}MHz - RAM: {mem_total} ({mem_avail} Available)"
    )
    output.print_color(Fore.CYAN, " " + _get_version_info())
    print()
    print(f" Started at {start_time}")
    print("")

    print("Connection Status:")
    print(f" {network.check_ipv4_connection()}")
    print(f" {network.check_ipv6_connection()}")
    print()


# noinspection PyUnusedLocal
def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        # check to see if we are a worker, or the main process
        if current_process().name == "MainProcess":
            output.empty()
            output.norm("Scan cancelled by user.")
            _shutdown()

        try:
            active_children()
        except Exception:
            # we don't care if this fails
            pass

        sys.exit(1)


def _shutdown():
    global _start_time, _monitor, _has_shutdown

    if _has_shutdown:
        return

    _has_shutdown = True
    output.debug("Shutting down...")

    elapsed = datetime.now() - _start_time
    mem_res = "{0:cM}".format(Size(_monitor.peak_mem_res))
    reporter.register_info("peak_memory", _monitor.peak_mem_res)

    output.empty()

    output.norm(f"Completed (Elapsed: {str(elapsed)} - Peak Memory: {mem_res})")

    if reporter.get_output_file() != "":
        with Spinner() as spinner:
            reporter.save_output(spinner)


def _get_locale() -> str:
    # get the locale
    try:
        locale.setlocale(locale.LC_ALL, "")
        lcl = locale.getdefaultlocale()
    except Exception as error:
        print(
            f"Unable to get Locale: {str(error)} - attempting to force locale to en_US.utf8"
        )

        try:
            if platform.system() == "Darwin":
                locale.setlocale(locale.LC_ALL, "EN_US")
            else:
                locale.setlocale(locale.LC_ALL, "en_US.utf8")

            lcl = locale.getdefaultlocale()
        except Exception as err:
            print(f"Unable to set locale: {str(err)}")

            return "(Unknown locale)"

    if lcl is not None:
        loc = f"{lcl[0]}.{lcl[1]}"
    else:
        loc = "(Unknown locale)"

    return loc


def _set_basic_info():
    reporter.register_info("start_time", int(time.time()))
    reporter.register_info("yawast_version", get_version())
    reporter.register_info(
        "python_version",
        f"{''.join(sys.version.splitlines())} ({platform.python_implementation()})",
    )
    reporter.register_info("openssl_version", ssl.OPENSSL_VERSION)
    reporter.register_info("platform", platform.platform())
    reporter.register_info("options", str(sys.argv))
    reporter.register_info("encoding", _get_locale())


def _get_version_info() -> str:
    try:
        data, code = network.http_json("https://pypi.org/pypi/yawast/json")
    except Exception:
        output.debug_exception()

        return "Supported Version: (Unable to get version information)"

    if code != 200:
        ret = "Supported Version: (PyPi returned an error code while fetching current version)"
    else:
        if "info" in data and "version" in data["info"]:
            ver = cast(version.Version, version.parse(get_version()))
            curr_version = cast(version.Version, version.parse(data["info"]["version"]))

            ret = f"Supported Version: {curr_version} - "

            if ver == curr_version:
                ret += "You are on the latest version."
            elif ver > curr_version or "dev" in get_version():
                ret += "You are on a pre-release version. Take care."
            else:
                ret += "Please update to the current version."
        else:
            ret = "Supported Version: (PyPi returned invalid data while fetching current version)"

    return ret


class _KeyMonitor:
    busy = False

    def wait_task(self):
        if sys.stdout.isatty():
            while self.busy:
                try:
                    with utils.INPUT_LOCK:
                        key = getchar()

                    if key != "":
                        output.debug(f"Received from keyboard: {key}")

                        if key == "d":
                            output.toggle_debug()

                    time.sleep(0.1)
                except Exception:
                    output.debug_exception()

                    self.busy = False
        else:
            # if this isn't a TTY, no point in doing any of this
            self.busy = False

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.wait_task).start()

        return self

    def __exit__(self, exception, value, tb):
        self.busy = False

        if exception is not None:
            return False


class _ProcessMonitor:
    WARNING_THRESHOLD = 100 * 1024 * 1024

    busy = False

    def __init__(self):
        self.process = psutil.Process()
        self.peak_mem_res = 0
        self.low_mem_warning = False

    def monitor_task(self):
        if sys.stdout.isatty():

            while self.busy:
                try:
                    info = self._get_info()
                    output.debug(info)

                    time.sleep(5)
                except Exception:
                    output.debug_exception()

                    self.busy = False
        else:
            # if this isn't a TTY, no point in doing any of this
            self.busy = False

    def _get_info(self) -> str:
        from yawast.external.memory_size import Size

        # prime the call to cpu_percent, as the first call doesn't return useful data
        self.process.cpu_percent()

        # force a collection; not ideal, but seems to help
        gc.collect(2)

        # use oneshot() to cache the data, so we minimize hits
        with self.process.oneshot():
            pct = self.process.cpu_percent()

            times = self.process.cpu_times()
            mem = self.process.memory_info()
            mem_res = "{0:cM}".format(Size(mem.rss))
            mem_virt = "{0:cM}".format(Size(mem.vms))

            if mem.rss > self.peak_mem_res:
                self.peak_mem_res = mem.rss
                output.debug(f"New high-memory threshold: {self.peak_mem_res}")

            thr = self.process.num_threads()

            vm = psutil.virtual_memory()
            mem_total = "{0:cM}".format(Size(vm.total))
            mem_avail_bytes = vm.available
            mem_avail = "{0:cM}".format(Size(vm.available))

            if mem_avail_bytes < self.WARNING_THRESHOLD and not self.low_mem_warning:
                self.low_mem_warning = True

                output.error(f"Low RAM Available: {mem_avail}")

            cons = -1
            try:
                cons = len(self.process.connections(kind="inet"))
            except Exception:
                # we don't care if this fails
                output.debug_exception()

            cpu_freq = psutil.cpu_freq()

        info = (
            f"Process Stats: CPU: {pct}% - Sys: {times.system} - "
            f"User: {times.user} - Res: {mem_res} - Virt: {mem_virt} - "
            f"Available: {mem_avail}/{mem_total} - Threads: {thr} - "
            f"Connections: {cons} - CPU Freq: "
            f"{int(cpu_freq.current)}MHz/{int(cpu_freq.max)}MHz - "
            f"GC Objects: {len(gc.get_objects())}"
        )

        return info

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.monitor_task).start()

        return self

    def __exit__(self, exception, value, tb):
        self.busy = False

        if exception is not None:
            return False
