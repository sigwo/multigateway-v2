#!/bin/bash

HOME=/root

cd $HOME
./mgw_stop.sh
sleep 5
./mgw_start.sh

exit $?
