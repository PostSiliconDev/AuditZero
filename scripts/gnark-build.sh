#!/bin/bash

go build -o target/build ./bins/gnark-build || exit 1
./target/build