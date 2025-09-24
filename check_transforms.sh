#!/usr/bin/env bash

for IP in $(cat ike-hosts.txt); do
    if [ -f "$IP"-valid-transform-sets.txt ]; then
        TRANSFORM_FILE="${IP}-valid-transform-sets.txt"
        for transform in $(cat $TRANSFORM_FILE); do
            echo -e "ike-scan --trans ${transform} -P -M -A -n FakeID ${IP}"
            ike-scan --trans ${transform} -P -M -A -n FakeID ${IP} | tee -a ike-scan-valid-transform-set-${IP}.log
        done
    fi
done | tee check-FakeID-with-valid-transform-sets-full.log
