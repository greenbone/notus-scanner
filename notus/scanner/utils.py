# Copyright (C) 2014-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import atexit
import signal

import logging

from functools import partial
from logging.handlers import SysLogHandler, WatchedFileHandler
from pathlib import Path
from typing import Optional, Union

import psutil

from .__version__ import __version__


logger = logging.getLogger(__name__)


def go_to_background() -> None:
    """Daemonize the running process."""
    try:
        if os.fork():
            sys.exit()
    except OSError as errmsg:
        logger.error("Fork failed: %s", errmsg)
        sys.exit(1)


def create_pid(pid_file: str) -> bool:
    """Check if there is an already running daemon and creates the pid file.
    Otherwise gives an error."""

    pid = str(os.getpid())
    new_process = psutil.Process(int(pid))
    new_process_name = new_process.name()

    pid_path = Path(pid_file)

    if pid_path.is_file():
        process_name = None
        current_pid = pid_path.read_text(encoding="utf-8")

        try:
            process = psutil.Process(int(current_pid))
            process_name = process.name()
        except psutil.NoSuchProcess:
            pass

        if process_name == new_process_name:
            logger.error(
                "There is an already running process. See %s.",
                str(pid_path.absolute()),
            )
            return False
        else:
            logger.debug(
                "There is an existing pid file '%s', but the PID %s belongs to "
                "the process %s. It seems that %s was abruptly stopped. "
                "Removing the pid file.",
                str(pid_path.absolute()),
                current_pid,
                process_name,
                new_process_name,
            )

    try:
        pid_path.write_text(pid, encoding="utf-8")
    except (FileNotFoundError, PermissionError) as e:
        logger.error(
            "Failed to create pid file %s. %s", str(pid_path.absolute()), e
        )
        return False

    return True


def exit_cleanup(
    pid_file: str,
    _signum=None,
    _frame=None,
) -> None:
    """Removes the pid_file before ending the daemon."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    pid_path = Path(pid_file)

    if not pid_path.is_file():
        return

    with pid_path.open(encoding="utf-8") as f:
        if int(f.read()) == os.getpid():
            logger.debug("Finishing daemon process")
            pid_path.unlink()
            sys.exit()


def init_signal_handler(pid_file: str):
    atexit.register(exit_cleanup, pid_file=pid_file)
    signal.signal(signal.SIGTERM, partial(exit_cleanup, pid_file))
    signal.signal(signal.SIGINT, partial(exit_cleanup, pid_file))


def init_logging(
    name: str,
    log_level: Union[int, str],
    *,
    log_file: Optional[str] = None,
    foreground: Optional[bool] = False,
):

    rootlogger = logging.getLogger()
    rootlogger.setLevel(log_level)

    if foreground:
        console = logging.StreamHandler()
        console.setFormatter(
            logging.Formatter(
                f"%(asctime)s {name}: %(levelname)s: (%(name)s) %(message)s"
            )
        )
        rootlogger.addHandler(console)
    elif log_file:
        logfile = WatchedFileHandler(log_file)
        logfile.setFormatter(
            logging.Formatter(
                f"%(asctime)s {name}: %(levelname)s: (%(name)s) %(message)s"
            )
        )
        rootlogger.addHandler(logfile)
    else:
        syslog = SysLogHandler("/dev/log")
        syslog.setFormatter(
            logging.Formatter(f"{name}: %(levelname)s: (%(name)s) %(message)s")
        )
        rootlogger.addHandler(syslog)

    return rootlogger
