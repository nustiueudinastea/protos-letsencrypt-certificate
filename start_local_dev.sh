#!/bin/bash


docker run \
       --rm \
       -ti \
       -v "$PWD":/go/src/letsencrypt-certificate \
       -w /go/src/letsencrypt-certificate \
       --name letsencrypt-certificate-dev \
       --hostname letsencrypt-certificate-dev \
       --network protosnet \
       golang:1.13 \
       /bin/bash
       #go run --race letsencrypt-certificate.go --loglevel debug --interval 20 start
