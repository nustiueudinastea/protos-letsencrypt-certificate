#!/bin/bash

exec /go/src/letsencrypt-certificate/letsencrypt-certificate --loglevel debug --interval 180 start
