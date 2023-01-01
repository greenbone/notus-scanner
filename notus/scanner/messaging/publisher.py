# Copyright (C) 2021-2023 Greenbone Networks GmbH
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

from abc import ABC, abstractmethod

from ..messages.message import Message


class Publisher(ABC):
    """An Abstract Base Class (ABC) for publishing Messages

    When updating to Python > 3.7 this should be converted into a
    typing.Protocol
    """

    @abstractmethod
    def publish(self, message: Message) -> None:
        raise NotImplementedError()
