from datetime import datetime, timedelta
from typing import Dict, List
from enum import Enum
import hashlib

from notus.scanner.messages.start import ScanStartMessage


class HostNameDecision(Enum):
    CONTINUE = 0  # hostname is not yet verified or is missing
    STOP = 1  # hostname has been already verified


class HostNameCache:
    def __init__(self, period: timedelta):
        self.period = period
        self.lookup: Dict[str, List[bytes]] = {}
        self.called: datetime = datetime.now()

    @staticmethod
    def hash(hostname: str) -> bytes:
        hasher = hashlib.sha1()
        hasher.update(bytes(hostname, "utf-8"))
        return hasher.digest()

    def __in_time(self) -> bool:
        return datetime.now() < self.called + self.period

    def verify(self, msg: ScanStartMessage) -> HostNameDecision:
        if not msg.host_name or not msg.scan_id:
            return HostNameDecision.CONTINUE
        hashsum = self.hash(msg.host_name)
        if self.__in_time():
            cache = self.lookup.get(msg.scan_id, [])
            for cached_hashsum in cache:
                if hashsum == cached_hashsum:
                    return HostNameDecision.STOP

            cache.append(hashsum)
            self.lookup[msg.scan_id] = cache
            return HostNameDecision.CONTINUE
        else:
            self.called = datetime.now()
            self.lookup = {}

            return HostNameDecision.CONTINUE
