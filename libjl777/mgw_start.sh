#!/bin/bash

MGWTRIPLET=1 #Set to 1 for BTCD triplet and 2 for BTC triplet
MGWHOME=~/mgw2/libjl777
MGWLOG=~/mgw.log

# Pre-flight checkups

function checktrip1 {
  pgrep SuperNET >/dev/null && { echo "MGW seems to be already running. Run ./mgw_stop.sh first if you want to restart."; exit 1; } 
  pgrep BitcoinDarkd >/dev/null || { echo "BTCD Daemon is not running! Start it and try again."; exit 1; }
  pgrep vericoind >/dev/null || { echo "VRC Daemon is not running! Start it and try again."; exit 1; }
  pgrep dashd >/dev/null || { echo "DASH Daemon is not running! Start it and try again."; exit 1; }
  pgrep Influxd >/dev/null || { echo "INFX Daemon is not running! Start it and try again."; exit 1; }
  pgrep opalcoind >/dev/null || { echo "OPAL Daemon is not running! Start it and try again."; exit 1; }
  pgrep syscoind >/dev/null || { echo "SYS Daemon is not running! Start it and try again."; exit 1; }
  ps ax | grep -q "[c]lasses nxt.Nxt" || { echo "Nxt is not running! Start it and try again."; exit 1; }
}
function checktrip2 {
  pgrep SuperNET >/dev/null && { echo "MGW seems to be already running. Run ./mgw_stop.sh first if you want to restart."; exit 1; }
  pgrep bitcoind > /dev/null || { echo "BTC Daemon is not running! Start it and try again."; exit 1; }
  pgrep dogecoind > /dev/null || { echo "DOGE Daemon is not running! Start it and try again."; exit 1; }
  pgrep litecoind > /dev/null || { echo "LTC Daemon is not running! Start it and try again."; exit 1; }
  ps ax | grep -q "[c]lasses nxt.Nxt" || { echo "Nxt is not running! Start it and try again."; exit 1; }
}
checktrip${MGWTRIPLET}

# Prepare log file

echo "logfile $MGWLOG" > .screenlog
if [ ! -f $MGWLOG ]; then
    touch $MGWLOG
else
    mv $MGWLOG $MGWLOG.bak
    echo "Preserving previous MGW log as $MGWLOG.bak"
    touch $MGWLOG
fi

# Start detached screen and MGW main process

screen -q -wipe
pgrep screen && screen -X -S mgw quit
sleep 1
echo "Launching MGW main process ..."
cd $MGWHOME
screen -d -m -S mgw -c ~/.screenlog -L
rm ~/.screenlog
echo "Logfile: $MGWLOG"
sleep 5
screen -S mgw -X stuff './launch'$(echo -ne '\015')
tail -f $MGWLOG | while read LOGLINE
do
   [[ "${LOGLINE}" == "MGW bind"* ]] && pkill -P $$ tail
done
echo "MGW main process started."
echo "-------------------------"

# Start coins in the triplet

SNPID=$(pgrep SuperNET)
function starttrip1 {
  # Start coin 1 - BTCD
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"BTCD\"}'" > /proc/$SNPID/fd/0
  echo -n "BTCD Gateway Starting... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"BTCD  [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"BTCD circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 2 - VRC
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"VRC\"}'" > /proc/$SNPID/fd/0
  echo -n "VRC Gateway Starting... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"VRC   [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"VRC circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 3 - DASH
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"DASH\"}'" > /proc/$SNPID/fd/0
  echo -n "DASH Gateway Starting... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"DASH  [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"DASH circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 4 - INFX
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"INFX\"}'" > /proc/$SNPID/fd/0
  echo -n "INFX Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"INFX  [lag 5    ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"INFX circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 5 - OPAL
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"OPAL\"}'" > /proc/$SNPID/fd/0
  echo -n "OPAL Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"OPAL  [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"OPAL circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 6 - SYS
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"SYS\"}'" > /proc/$SNPID/fd/0
  echo -n "SYS Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"SYS   [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"SYS circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
}

function starttrip2 {
  # Start coin 1 - BTC
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"BTC\"}'" > /proc/$SNPID/fd/0
  echo -n "BTC Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"BTC   [lag 3    ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"BTC circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 2 - DOGE
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"DOGE\"}'" > /proc/$SNPID/fd/0
  echo -n "DOGE Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"DOGE  [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"DOGE circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
  # Start coin 3 - LTC
  echo "./BitcoinDarkd SuperNET '{\"plugin\":\"ramchain\",\"method\":\"create\",\"coin\":\"LTC\"}'" > /proc/$SNPID/fd/0
  echo -n "LTC Gateway Starting..."
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"LTC   [lag 10   ]"* ]] && pkill -P $$ tail
  done
  echo -n "Minimum confirmations reached... "
  tail -f $MGWLOG | while read LOGLINE
  do
     [[ "${LOGLINE}" == *"LTC circulation"* ]] && pkill -P $$ tail
  done
  echo "Done"
}

starttrip${MGWTRIPLET}

exit $?
