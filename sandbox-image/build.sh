#!/bin/bash

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o minit landzero.net/x/os/minit/cmd/minit

docker build -t yanke/bunker-sandbox .
