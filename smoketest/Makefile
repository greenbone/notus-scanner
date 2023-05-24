# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

C_NETWORK_NAME := notus-smoketests
C_IMAGE_PRFX := ghcr.io/greenbone
C_IMAGE_TAG := latest
C_IMAGE_NAME := ${C_IMAGE_PRFX}/notus-scanner-smoketest:${C_IMAGE_TAG}
C_SLACKWARE := ghcr.io/greenbone/scanner-lab-slackware:latest

RUN_CONTAINER = docker run --rm --network ${C_NETWORK_NAME}
RUN_CONTAINER_D := ${RUN_CONTAINER} -d
RUN_CONTAINER_P := ${RUN_CONTAINER} --privileged 

ifndef GO
	GO := go
endif
GO_BUILD := CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ${GO} build -o

all: build create-network slackware run stop-slackware delete-network

build:
	cd .. && DOCKER_BUILDKIT=1 docker build -f smoketest/Dockerfile -t ${C_IMAGE_NAME} .

build-cmd:
	mkdir -p bin/
	${GO_BUILD} bin/run-notus-smoketests cmd/tests/main.go

create-network:
	- docker network create -d bridge ${C_NETWORK_NAME}

delete-network:
	- docker network rm ${C_NETWORK_NAME}

run:
	${RUN_CONTAINER_P} ${C_IMAGE_NAME}

interactive:
	${RUN_CONTAINER_P} -it ${C_IMAGE_NAME} bash

slackware:
	${RUN_CONTAINER_D} --name "nst_slackware" ${C_SLACKWARE}

stop-slackware:
	docker stop nst_slackware


