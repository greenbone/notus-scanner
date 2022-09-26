#!/usr/bin/env bash
# Is a convenience script to start redis, ospd-openvas and notus

shutdown() {
  kill $(cat /run/ospd/ospd.pid) || true
  kill $(cat /tmp/mosquitto.pid) || true
  redis-cli -s /run/redis/redis.sock SHUTDOWN
}

trap shutdown EXIT

set -e
mosquitto -c /etc/mosquitto.conf &
redis-server /etc/redis/redis.conf
# currently there is a bug within the gather-package-list for slckware
sed -i 's|ssh/login/slackpack_notus|ssh/login/package_list_notus|' /var/lib/openvas/plugins/gather-package-list.nasl
ospd-openvas --disable-notus-hashsum-verification True \
  -u /run/ospd/ospd-openvas.sock \
  -l /var/log/gvm/ospd.log
wait_turn=0
while [ ! -S /run/ospd/ospd-openvas.sock ]; do
  if [ $wait_turn -eq 10 ]; then
    printf "too many attempts to find ospd-openvas.sock\n"
    exit 1
  fi
  printf "waiting for ospd-openvas.socket ($wait_turn)\n"
  sleep 1
  wait_turn=$(($wait_turn + 1))
done
notus-scanner -l /var/log/gvm/notus.log --disable-hashsum-verification true
#ospd-scans --host nst_slackware --user gvm --password gvm --policies GatherPackageList --cmd start-finish
run-notus-smoketests
