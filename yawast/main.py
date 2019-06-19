import locale
import platform
import signal
import ssl
import sys
import threading
import time
from datetime import datetime
from multiprocessing import current_process, active_children

import psutil
from psutil import Process

from yawast import command_line
from yawast._version import get_version
from yawast.external.get_char import getchar
from yawast.external.memory_size import Size
from yawast.shared import output, network


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = command_line.build_parser()
    args, urls = parser.parse_known_args()

    # setup the output system
    output.setup(args.debug, args.nocolors)

    # if we made it this far, it means that the parsing worked.
    command_line.process_urls(urls)

    # we are good to keep going
    print_header()

    try:
        with _KeyMonitor():
            with _ProcessMonitor() as pm:
                start_time = datetime.now()

                args.func(args, urls)

                elapsed = datetime.now() - start_time
                mem_res = "{0:cM}".format(Size(pm.peak_mem_res))

                output.empty()
                output.norm(
                    f"Completed (Elapsed: {str(elapsed)} - Peak Memory: {mem_res})"
                )
    except KeyboardInterrupt:
        output.empty()
        output.error("Scan cancelled by user.")


def print_header():
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

            lcl = None

    if lcl is not None:
        loc = f"{lcl[0]}.{lcl[1]}"
    else:
        loc = "(Unknown locale)"

    start_time = time.strftime("%Y-%m-%d %H:%M:%S %Z (%z)", time.localtime())

    vm = psutil.virtual_memory()
    mem_total = "{0:cM}".format(Size(vm.total))
    mem_avail = "{0:cM}".format(Size(vm.available))

    cpu_freq = psutil.cpu_freq()
    cpu_max = int(cpu_freq.max)
    if cpu_max == 0:
        # in this case, we don't have a real max, so go with current
        cpu_max = int(cpu_freq.current)

    print(r"__   _____  _    _  ___   _____ _____ ")
    print(r"\ \ / / _ \| |  | |/ _ \ /  ___|_   _|")
    print(r" \ V / /_\ \ |  | / /_\ \\ `--.  | |  ")
    print(r"  \ /|  _  | |/\| |  _  | `--. \ | |  ")
    print(r"  | || | | \  /\  / | | |/\__/ / | |  ")
    print(r"  \_/\_| |_/\/  \/\_| |_/\____/  \_/  ")
    print("")
    print(
        f"YAWAST v{get_version()} - The YAWAST Antecedent Web Application Security Toolkit"
    )
    print(" Copyright (c) 2013-2019 Adam Caudill <adam@adamcaudill.com>")
    print(" Support & Documentation: https://github.com/adamcaudill/yawast")
    print(
        f" Python {''.join(sys.version.splitlines())} ({platform.python_implementation()})"
    )
    print(f" {ssl.OPENSSL_VERSION}")
    print(f" Platform: {platform.platform()} ({loc})")
    print(
        f" CPU(s): {psutil.cpu_count()}@{cpu_max}MHz - RAM: {mem_total} ({mem_avail} Available)"
    )
    print(f" Started at {start_time}")
    print("")

    print("Connection Status:")
    print(f" {network.check_ipv4_connection()}")
    print(f" {network.check_ipv6_connection()}")
    print("")


def signal_handler(sig, frame):
    # check to see if we are a worker, or the main process
    if current_process().name == "MainProcess":
        print()
        print("Shutting down...")

    try:
        active_children()
    except:
        # we don't care if this fails
        pass

    sys.exit(1)


class _KeyMonitor:
    busy = False

    def wait_task(self):
        if sys.stdout.isatty():
            while self.busy:
                try:
                    key = getchar()

                    if key != "":
                        output.debug(f"Received from keyboard: {key}")

                        if key == "d":
                            output.toggle_debug()

                    time.sleep(0.1)
                except Exception:
                    output.debug_exception()

                    self.busy = False

                    pass
        else:
            # if this isn't a TTY, no point in doing any of this
            self.busy = False

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.wait_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False

        if exception is not None:
            return False


class _ProcessMonitor:
    WARNING_THRESHOLD = 100 * 1024 * 1024

    busy = False

    def __init__(self):
        self.process = Process()
        self.peak_mem_res = 0

    def monitor_task(self):
        from yawast.external.memory_size import Size

        if sys.stdout.isatty():
            warning_displayed = False

            while self.busy:
                try:
                    # prime the call to cpu_percent, as the first call doesn't return useful data
                    self.process.cpu_percent(interval=1)

                    # use oneshot() to cache the data, so we minimize hits
                    with self.process.oneshot():
                        pct = self.process.cpu_percent()

                        times = self.process.cpu_times()
                        mem = self.process.memory_info()
                        mem_res = "{0:cM}".format(Size(mem.rss))
                        mem_virt = "{0:cM}".format(Size(mem.vms))

                        thr = self.process.num_threads()

                        vm = psutil.virtual_memory()
                        mem_total = "{0:cM}".format(Size(vm.total))
                        mem_avail_bytes = vm.available
                        mem_avail = "{0:cM}".format(Size(vm.available))

                        if (
                            mem_avail_bytes < self.WARNING_THRESHOLD
                            and not warning_displayed
                        ):
                            warning_displayed = True

                            output.error(f"Low RAM Available: {mem_avail}")

                        cons = -1
                        try:
                            cons = len(self.process.connections(kind="inet"))
                        except:
                            # we don't care if this fails
                            output.debug_exception()

                        if mem.rss > self.peak_mem_res:
                            self.peak_mem_res = mem.rss

                        cpu_freq = psutil.cpu_freq()

                    info = (
                        f"Process Stats: CPU: {pct}% - Sys: {times.system} - "
                        f"User: {times.user} - Res: {mem_res} - Virt: {mem_virt} - "
                        f"Available: {mem_avail}/{mem_total} - Threads: {thr} - "
                        f"Connections: {cons} - CPU Freq: "
                        f"{int(cpu_freq.current)}MHz/{int(cpu_freq.max)}MHz"
                    )

                    output.debug(info)

                    time.sleep(10)
                except Exception:
                    output.debug_exception()

                    self.busy = False

                    pass
        else:
            # if this isn't a TTY, no point in doing any of this
            self.busy = False

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.monitor_task).start()

        return self

    def __exit__(self, exception, value, tb):
        self.busy = False

        if exception is not None:
            return False