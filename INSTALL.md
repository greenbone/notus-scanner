# Installation

To install Notus Python 3.9 and later is required.

Besides Python Notus Scanner also needs to have

- paho-mqtt
- psutil
- python-gnupg

To retrieve package-lists and publish results Notus needs a MQTT broker running.

To install a local MQTT-broker on Debian you can execute:

```
$ apt-get install mosquitto 
```

To configure mosquitto please consolidate [man mosquitto.conf](https://mosquitto.org/man/mosquitto-conf-5.html).

To install notus you can use poetry to create a wheel package

```
> poetry install
> poetry build -f wheel
```

which you can then use to install it via `pip`:

```
> pip install notus_scanner-22.4.0-py3-none-any.whl
```

After that you should create a configuration.


# Configuration

If you want a configuration system-wide you should create it in `/etc/gvm/notus-scanner.toml`;
if you want to use a user specific configuration create it in `~/.config/notus-scanner.toml`.

```toml
[notus-scanner]
mqtt-broker-address = "localhost"
mqtt-broker-port = "1883"
products-directory = "/var/lib/notus/products"
pid-file = "/var/run/notus-scanner/notus-scanner.pid"
log-file = "/var/log/notus-scanner/notus-scanner.log"
log-level = "INFO"
disable-hashsum-verification = false
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
|products-directory|NOTUS_SCANNER_PRODUCTS_DIRECTORY|/var/lib/notus/products|Directory for loading product advisories|
|disable-hashsum-verification|NOTUS_DISABLE_HASHSUM_VERIFICATION|false|To disable hashsum verification of products|

# Starting

To start Notus execute `notus-scanner` it does lookup the configuration in either `/etc/gvm/notus-scanner.toml` or in `~/.config/notus-scanner.toml` and it will start in background.

For more information consolidate `notus-scanner --help`.
