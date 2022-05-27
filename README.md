![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Notus Scanner <!-- omit in toc -->

[![Build and test](https://github.com/greenbone/notus-scanner/actions/workflows/ci-python.yml/badge.svg)](https://github.com/greenbone/notus-scanner/actions/workflows/ci-python.yml)
[![codecov](https://codecov.io/gh/greenbone/notus-scanner/branch/main/graph/badge.svg?token=LaduLacbWO)](https://codecov.io/gh/greenbone/notus-scanner)

Notus Scanner detects vulnerable products in a system environment. The scanning
method is to evaluate internal system information. It does this very fast and
even detects currently inactive products because it does not need to interact
with each of the products.

To report about vulnerabilities, Notus Scanner receives collected system
information on the one hand and accesses the vulnerability information from the
feed service on the other. Both input elements are in table form: the system
information is specific to each environment and the vulnerability information is
specific to each system type.

Notus Scanner integrates into the Greenbone Vulnerability Management framework
which allows to let it scan entire networks within a single task. Any
vulnerability test in the format of `.notus` files inside the Greenbone Feed
will be considered and automatically matched with the scanned environments.

A system environment can be the operating system of a host. But it could also be
containers like Docker or virtual machines. Neither of these need to be actively
running for scanning.

The Notus Scanner is implemented in Python and published under an Open Source
license. Greenbone Networks maintains and extends it since it is embedded in the
Greenbone Professional Edition as well as in the Greenbone Cloud Services.

Greenbone also keeps the vulnerability information up-to-date via the feed on a
daily basis. The `.notus` format specification is open and part of the
documentation.

## Table of Contents <!-- omit in toc -->

- [Installation](#installation)
  - [Requirements](#requirements)
- [Development](#development)
- [Configuration](#configuration)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Requirements

Python 3.7 and later is supported.

Besides Python Notus Scanner also needs to have

- paho-mqtt
- psutil
- python-gnupg

installed.

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

## Configuration

The configuration of notus-scanner can be done by providing a TOML config file.
Per default notus-scanner tries to load the settings from config files in the
following order: `~/.config/notus-scanner.toml`, `/etc/gvm/notus-scanner.toml`.

Alternatively the location of the to be loaded config file can be set via the
`-c`/`--config` command line argument. Setting a config file via command line
will ignore the default config files.

The settings are read from a `[notus-scanner]` [section](https://toml.io/en/v1.0.0#table).

Example config file:
```toml
[notus-scanner]
mqtt-broker-address = "1.2.3.4"
mqtt-broker-port = "1234"
products-directory = "/tmp/notus/advisories/products"
pid-file = "/tmp/notus-scanner.pid"
log-file = "/tmp/notus-scanner.log"
log-level = "DEBUG"
disable-hashsum-verification = true
```

Each setting can be overridden via an environment variable or command line
argument.

|Config|Environment|Default|Description|
|------|-----------|-------|-----------|
|log-file|NOTUS_SCANNER_LOG_FILE|syslog|File for log output|
|log-level|NOTUS_SCANNER_LOG_LEVEL|INFO|Minimum level for log output|
|mqtt-broker-address|NOTUS_SCANNER_MQTT_BROKER_ADDRESS|localhost|IP or DNS address of the MQTT broker|
|mqtt-broker-port|NOTUS_SCANNER_MQTT_BROKER_PORT|1883|Port of the MQTT broker|
|pid-file|NOTUS_SCANNER_PID_FILE|/run/notus-scanner/notus-scanner.pid|File for storing the process ID|
|products-directory|NOTUS_SCANNER_PRODUCTS_DIRECTORY|/var/lib/openvas/plugins/notus/products|Directory for loading product advisories|
|disable-hashsum-verification| NOTUS_DISABLE_HASHSUM_VERIFICATION | To disable hashsum verification of products |

## Support

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

Copyright (C) 2021-2022 Greenbone Networks GmbH

Licensed under the GNU Affero General Public License v3.0 or later.

[Greenbone Networks]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[autohooks]: https://github.com/greenbone/autohooks
[Greenbone Community Portal]: https://community.greenbone.net/
