#!/bin/bash

echo -n "Stopping Multigateway..."
pkill -15 SuperNET
echo "Done."
echo -n "Stopping screen process..."
pkill -9 screen
echo "Done."
pgrep tee && killall tee

exit $?
