#!/bin/bash

go build -o target/prove ./bins/gnark-prove || exit 1
./target/prove
