from datetime import timedelta
from time import sleep
from unittest import TestCase

from notus.scanner.hostname import HostNameCache, HostNameDecision
from notus.scanner.messages.start import ScanStartMessage


class HostnameCacheTestCase(TestCase):
    def create_start_scan(
        self, hostname: str, scan_id: str = "default"
    ) -> ScanStartMessage:
        return ScanStartMessage(
            scan_id=scan_id,
            host_ip="127.0.0.1",
            host_name=hostname,
            os_release="",
            package_list=[],
        )

    def test_continue_on_unknown_hostname(self):
        under_test = HostNameCache(timedelta(seconds=1)).verify
        result = under_test(self.create_start_scan("testhost"))
        self.assertEqual(HostNameDecision.CONTINUE, result)

    def test_continue_on_hostname_empty(self):
        under_test = HostNameCache(timedelta(minutes=1)).verify
        result = under_test(self.create_start_scan(""))
        self.assertEqual(HostNameDecision.CONTINUE, result)
        result = under_test(self.create_start_scan(""))
        self.assertEqual(HostNameDecision.CONTINUE, result)

    def test_continue_on_hostname_known_but_period_exceeded(self):
        under_test = HostNameCache(timedelta(microseconds=1)).verify
        under_test(self.create_start_scan("testhost"))
        sleep(1)
        result = under_test(self.create_start_scan("testhost"))
        self.assertEqual(HostNameDecision.CONTINUE, result)

    def test_stop_on_hostname_found(self):
        under_test = HostNameCache(timedelta(minutes=1)).verify
        result = under_test(self.create_start_scan("testhost"))
        self.assertEqual(HostNameDecision.CONTINUE, result)
        result = under_test(self.create_start_scan("testhost"))
        self.assertEqual(HostNameDecision.STOP, result)

    def test_continue_on_missing_scan_id(self):
        under_test = HostNameCache(timedelta(minutes=1)).verify
        result = under_test(self.create_start_scan("testhost", scan_id=""))
        self.assertEqual(HostNameDecision.CONTINUE, result)
        result = under_test(self.create_start_scan("testhost", scan_id=""))
        self.assertEqual(HostNameDecision.CONTINUE, result)

    def test_continue_on_hostname_known_but_different_scan_id(self):
        under_test = HostNameCache(timedelta(minutes=1)).verify
        result = under_test(self.create_start_scan("testhost"))
        self.assertEqual(HostNameDecision.CONTINUE, result)
        result = under_test(
            self.create_start_scan("testhost", scan_id="another one")
        )
        self.assertEqual(HostNameDecision.CONTINUE, result)
