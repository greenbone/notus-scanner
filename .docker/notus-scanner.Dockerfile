FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /notus

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gpg \
    gpg-agent \
    python3 \
    python3-pip \
    python3-rpm && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system notus && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group notus

COPY dist/* /notus

RUN python3 -m pip install /notus/*

RUN chown notus:notus /notus

USER notus

ENTRYPOINT [ "notus-scanner" ]
CMD ["-f", "--pid-file=/notus/notus-scanner.pid", "-b", "broker"]
