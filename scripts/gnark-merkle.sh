#!/bin/bash

go build -o target/merkle ./bins/gnark-merkle || exit 1
./target/merkle
