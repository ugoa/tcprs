#!/bin/bash
cargo b --release
if [ $? -ne 0 ]; then
   exit 1
fi
sudo setcap cap_net_admin=eip /home/dawei/Develop/Rust/tcprs/target/release/tcprs

/home/dawei/Develop/Rust/tcprs/target/release/tcprs &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM
wait $pid
