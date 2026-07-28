#!/usr/bin/bash
~/reo.sh GetAbility | grep -P '"ver": [1-9]' -B 2 | grep "{" | grep -oP '(".*?")'
