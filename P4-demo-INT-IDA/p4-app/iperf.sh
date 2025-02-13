#!/bin/bash

PORT=5555
TIME=10

print_usage () {
  echo "Usage: ./iperf.sh [-s|-c destination] [-h] [-p port] [-t time] -k total_packets_per_sec"
  echo "  -h|--help  :  Print usage."
  echo "  -s         :  Server mode which receives the data."
  echo "  -c         :  Client mode which sends the data. Requires destination."
  echo "  -p|--port  :  Port to use for server or to connect to. Default 50000."
  echo "  -t|--time  :  Number of seconds to run. Default 60 seconds."
  echo "  -k|--pkts  :  Number of packets per second to send."
  echo "  -s|--source-port  : Source port to send from as client"
}

while [[ $# -ge 1 ]]
do
  key="$1"
  shift

  # Case through the flags
  case $key in
    -h|--help)
      print_usage
      exit 1
    ;;
    -p|--server-port)
      PORT=$1
      shift
    ;;
    -c|--client)
      MODE='-c'
      DESTINATION=$1
      shift
    ;;
    -s|--server)
      MODE='-s'
    ;;
    -k|--pktps)
      PKTS=$1
      shift
    ;;
    -t|--time)
      TIME=$1
      shift
    ;;
    -r|--source-port)
      SOURCEPORT=$1
      shift
    ;;
    *)
    ;;
  esac
done

if [[ -z "$MODE" ]]
then
  echo "ERROR: You need a mode to use, either -c for client or -s for server."
  print_usage
  exit 1
fi

if [[ -z "$PKTS" ]]
then
  echo "ERROR: You need a total number of packets to send per second. See -k."
  print_usage
  exit 1
fi

if [[ $MODE == '-c' ]]
then
  if [[ -z "$DESTINATION" ]]
  then
    echo "ERROR: You need a destination in client mode. See -c."
    print_usage
    exit 1
  fi
  let BANDWIDTH=96*$PKTS
  iperf3 -u -c $DESTINATION -p $PORT -l 12 -b $BANDWIDTH -t $TIME -i 1
else
  # Accept 10MB at most and output every 1 second
  iperf3 -u -s -p $PORT -w 10M -i 1
fi
