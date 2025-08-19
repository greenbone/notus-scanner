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

RUN python3 -m pip install --break-system-packages poetry

RUN rm -rf dist && poetry build -f wheel

FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR off

WORKDIR /notus

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    adduser \
    gosu \
    gpg \
    gpg-agent \
    python3 \
    python3-pip \
    # gcc and python3-dev are required for psutil on arm
    gcc \
    python3-dev && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system notus && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group notus

COPY --from=builder /source/dist/* /notus/
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN python3 -m pip install  --break-system-packages /notus/*

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

RUN mkdir /run/notus-scanner &&\
    mkdir -p /var/lib/notus && \
    chown -R notus:notus /notus /var/lib/notus /run/notus-scanner && \
    chmod 755 /usr/local/bin/entrypoint

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD ["notus-scanner", "-f", "-b", "broker"]
