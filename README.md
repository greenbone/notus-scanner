![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# Notus Scanner <!-- omit in toc -->

Notus Scanner is vulnerability scanner for creating results from local security
checks (LSCs).

It is written in Python and can "execute" lots of LSCs in a fraction of the time
it takes using LSCs for the openvas scanner. This is being achieved through a
table-based approach instead of utilizing forks to run code.

Note that this scanner works hand-in-hand with a generator, which generates VT
metadata in the form of files that are used to provide information about
advisories and fixed packages.

## Table of Contents <!-- omit in toc -->

- [Installation](#installation)
  - [Requirements](#requirements)
- [Development](#development)
- [​Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Requirements

Python 3.7 and later is supported.

Besides Python Notus Scanner also needs to have

- paho-mqtt
- psutil
- rpm

installed.

The `rpm` is package is not available via pip. Therefore must be installed via
your distribution. For example via apt for our reference system Debian 10
Buster.

## Development

**notus-scanner** uses [poetry] for its own dependency management and build
process.

First install poetry via pip

  python3 -m pip install --user poetry

Afterwards run

  poetry install

in the checkout directory of **notus-scanner** (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards activate the git hooks for auto-formatting and linting via
[autohooks].

    poetry run autohooks activate

Validate the activated git hooks by running

    poetry run autohooks check

For using the `rpm` Python module you need to install the `python3-rpm` Debian
package

    sudo apt install python3-rpm

To be able to use the `rpm` module you need to make the Python virtual
environment created by poetry aware of the system wide Python packages.

    python3 -m venv --system-site-packages .venv

## ​Support

For any question on the usage of Notus Scanner please use the
[Greenbone Community Portal]. If you found a problem with the software, please
create an issue on GitHub. If you are a Greenbone customer you may alternatively
or additionally forward your issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks GmbH][Greenbone Networks]

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/notus-scanner/pulls)
on GitHub. Bigger changes need to be discussed with the development team via the
[issues section at GitHub](https://github.com/greenbone/notus-scanner/issues)
first.

## License

Copyright (C) 2021 Greenbone Networks GmbH

Licensed under the GNU Affero General Public License v3.0 or later.

[Greenbone Networks]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[autohooks]: https://github.com/greenbone/autohooks
[Greenbone Community Portal]: https://community.greenbone.net/
