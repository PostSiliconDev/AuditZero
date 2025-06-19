#!/bin/bash

go build -o target/prove ./bins/gnark-build || exit 1
./target/prove