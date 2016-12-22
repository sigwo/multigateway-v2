#!/bin/bash

echo -n "Stopping Multigateway..."
pkill -15 SuperNET
echo "Done."
echo -n "Stopping screen process..."
killall screen
echo "Done."
pgrep tee >/dev/null && killall tee

exit $?
