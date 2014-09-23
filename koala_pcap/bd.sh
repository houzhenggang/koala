#!/bin/bash
cd build/
rm -fr *
cmake ..
make
src/yf_main -i eth0 -o eth0 host 192.168.0.234 and port 80