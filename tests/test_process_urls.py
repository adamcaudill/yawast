#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from tests import utils
from yawast import command_line


class TestProcessUrls(TestCase):
    def test_process_urls_empty(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn(
            "YAWAST Error: You must specify at least one URL.", stderr.getvalue()
        )

    def test_process_urls_maybe_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "adamcaudill.com"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        self.assertEqual("", stderr.getvalue())

    def test_process_urls_invalid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "erty://adamcaudill.com"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid URL Specified", stderr.getvalue())

    def test_process_urls_invalid_wss(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "wss://adamcaudill.com"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid URL Specified", stderr.getvalue())

    def test_process_urls_invalid_shttp(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "shttp://adamcaudill.com"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid URL Specified", stderr.getvalue())

    def test_process_urls_invalid_ftp(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "ftp://adamcaudill.com"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid URL Specified", stderr.getvalue())

    def test_process_urls_invalid_port(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com:99999"])

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid URL Specified", stderr.getvalue())

    def test_process_urls_valid_port(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com:9999"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        self.assertEqual("", stderr.getvalue())

    def test_process_urls_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        self.assertEqual("", stderr.getvalue())

    def test_process_urls_two_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(
            ["scan", "http://adamcaudill.com", "http://google.com"]
        )

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        self.assertEqual("", stderr.getvalue())

    def test_process_urls_unknown_param(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "--dfghjk"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        self.assertIn("YAWAST Error: Invalid parameter", stderr.getvalue())
