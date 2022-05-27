FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /notus

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gosu \
    gpg \
    gpg-agent \
    python3 \
    python3-pip \
    python3-rpm \
    # gcc and python3-dev are required for psutil on arm
    gcc \
    python3-dev&& \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system notus && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group notus

COPY dist/* /notus
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN python3 -m pip install /notus/*

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

RUN chown notus:notus /notus && \
    chmod 755 /usr/local/bin/entrypoint

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD ["notus-scanner", "-f", "--pid-file=/notus/notus-scanner.pid", "-b", "broker"]
