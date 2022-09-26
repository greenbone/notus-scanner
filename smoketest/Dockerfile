FROM greenbone/vulnerability-tests AS nasl-feed
# use latest version
RUN mv `ls -d /var/lib/openvas/* | sort -r | head -n 1`/vt-data/nasl /nasl

# we just care about the newest gather packagelist; this should trigger notus
# down the line therefore we created a own policy.
FROM golang AS feed
WORKDIR /usr/local/src
#does not pickup latest version from main but sticks to latest version
#RUN go install github.com/greenbone/ospd-openvas/smoketest/cmd/feed-preparer@main
RUN git clone --depth 1 https://github.com/greenbone/ospd-openvas.git 
WORKDIR /usr/local/src/ospd-openvas/smoketest
RUN make build-cmds
RUN cp bin/ospd-policy-feed /go/bin/feed-preparer
COPY --from=nasl-feed /nasl /var/lib/openvas/plugins 
COPY --from=ghcr.io/greenbone/scanner-lab-slackware:latest /usr/local/src/notus /usr/local/src/notus
RUN mkdir -p /usr/local/src/policies 
COPY smoketest/gatherpackagelist-c18bb781-3740-44c2-aa01-1b73a00066e8.xml /usr/local/src/policies
RUN feed-preparer -p /usr/local/src/policies -t /usr/local/src/plugins
RUN mkdir /usr/local/src/ns
COPY . /usr/local/src/ns/
WORKDIR /usr/local/src/ns/smoketest
RUN make build-cmd
RUN cp bin/run-notus-smoketests /usr/local/bin/run-notus-smoketests

FROM debian:stable-slim as builder
COPY . /source
WORKDIR /source
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    python3 \
    python-is-python3 \
    python3-pip && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install poetry
RUN rm -rf dist && poetry build -f wheel

# we want to start ospd-openvas, mosquitto, redis as well as notus on the same
# machine to somewhat simulate an appliance setup.
FROM greenbone/ospd-openvas:unstable
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR off

WORKDIR /usr/local/src/notus
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    mosquitto \
    redis \
    gpg \
    gpg-agent \
    python3 \
    python3-pip \
    # gcc and python3-dev are required for psutil on arm
    gcc \
    python3-dev && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

#RUN addgroup --gid 1001 --system notus && \
#    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group notus

COPY --from=builder /source/dist/* /usr/local/src/notus/

RUN python3 -m pip install /usr/local/src/notus/*

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

RUN mkdir /run/notus-scanner &&\
    mkdir -p /var/lib/notus && \
    chown -R ospd-openvas:redis /var/lib/notus /run/notus-scanner

COPY --from=feed /usr/local/src/plugins /var/lib/openvas/plugins
COPY --from=feed /usr/local/src/policies /usr/local/src/policies
COPY --from=feed /usr/local/src/notus /var/lib/notus
COPY --from=feed /usr/local/bin/run-notus-smoketests /usr/local/bin/run-notus-smoketests
COPY --chown=ospd-openvas:redis smoketest/hosts.txt /usr/local/src/notus/hosts.txt
# TODO may change dir structure to just copy a folder instead of file to spare additional chown
COPY --chown=ospd-openvas:redis smoketest/redis.conf /etc/redis/redis.conf
RUN chown -R ospd-openvas:redis /etc/redis
COPY --chmod=0755 smoketest/scripts/start.sh /usr/local/bin/start

# RUN mkdir -p /var/run/ospd/
# RUN chown ospd-openvas:redis /var/run/ospd
# RUN touch /etc/openvas/openvas_log.conf
# RUN chown ospd-openvas:redis /etc/openvas/openvas_log.conf
#
RUN mkdir /run/redis
RUN chown ospd-openvas:redis /run/redis
RUN mkdir -p /var/run/ospd/
RUN chown ospd-openvas:redis /var/run/ospd
RUN touch /etc/openvas/openvas_log.conf
RUN chown ospd-openvas:redis /etc/openvas/openvas_log.conf
RUN chown ospd-openvas:redis /var/log/gvm
RUN mkdir /run/mosquitto
RUN echo "allow_anonymous true" >> /etc/mosquitto.conf
RUN echo "pid_file /tmp/mosquitto.pid" >> /etc/mosquitto.conf
RUN echo "log_dest file /tmp/mosquitto.log" >> /etc/mosquitto.conf
RUN echo "persistence_location = /tmp/" >> /etc/mosquitto.conf
RUN echo "persistence true" >> /etc/mosquitto.conf
RUN echo "mqtt_server_uri = localhost:1883" >> /etc/openvas/openvas.conf
RUN chown mosquitto:mosquitto /run/mosquitto
RUN mkdir -p /var/log/mosquitto/
RUN chown mosquitto:mosquitto /var/log/mosquitto
RUN chmod 774 /var/log/mosquitto
CMD /usr/local/bin/start
