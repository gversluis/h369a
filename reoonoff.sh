#!/bin/bash
#USER=$(~/reo.sh GetOnline | jq '
#(.User | length) as $count |
#	if $count > 1 then
#		"Reo in use by \(.User | map(.ip))"
#	else
#		""
#	end
#')
#if [[ -n $USER && "$USER" != '""' ]]; then echo "$USER" && exit; fi
#MASK=$(~/reo.sh GetMask)
#if [[ $MASK == "(Sec) Host not found"* ]]; then echo "No connection" && exit 1; fi
#HASMASK=$(echo $MASK | jq '.Mask.area != null and (.Mask.area | length > 0) == false')
set -o pipefail
HASMASK=$(~/reo.sh GetPowerLed | jq '.PowerLed.state=="On"')
if [ $? -ne 0 ]; then exit; fi
if [ -z $1 ]; then
  # ~/reo.sh GetMask
	echo -n "Reo: "
	if [[ "$HASMASK" == "true" ]]; then echo "Masked"; else echo "Watching"; fi
  echo ""
  echo "$0 on / true / 1 - to turn cam on (remove all privacy masks)"
  echo "$0 off / false / 0 - to turn cam off (addd full screen privacy mask)"
  echo ""
else
	if [[ "${1,,}" == "on" || "$1" == "1" || "${1,,}" == "true" ]]; then
		[[ "$HASMASK" != "true" ]] && echo "Reo already on" && exit
    echo "Removing mask..."
		~/reo.sh SetMask '
			{
				"Mask": {
					"channel": 0,
					"enable": 1,
					"area": [
					]
				}
			}
		'
		sleep 1
    echo "Disable power led..."	# we do not want betray our camera
		~/reo.sh SetPowerLed '{"PowerLed":{"state":"Off","channel":0}}'
		sleep 1
    echo "Moving camera to room..."
		~/reo.sh PtzCtrl '{"channel":0,"id":2,"op":"ToPos","speed":32}' # id 1=off
	else
		[[ "$HASMASK" == "true" ]] && echo "Reo already off" && exit
    echo "Enable power led..."
		~/reo.sh SetPowerLed '{"PowerLed":{"state":"On","channel":0}}'
		sleep 1
    echo "Adding mask..."
		~/reo.sh SetMask '
			{
					"Mask": {
							"channel": 0,
							"enable": 1,
							"area": [{
											"screen": {
													"width": 1079,
													"height": 607
											},
											"block": {
													"x": 0,
													"y": 0,
													"width": 1079,
													"height": 607,
													"color": 0,
													"layer": 0
											}
							}]
					}
			}
		'
		sleep 1
    echo "Moving camera away..."
		~/reo.sh PtzCtrl '{"channel":0,"id":1,"op":"ToPos","speed":32}' # id 1=off
	fi
fi
