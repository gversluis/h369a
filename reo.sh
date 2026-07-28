#!/bin/bash
#API# Source: https://gist.github.com/jasonk/4772d1cd5154069cfc9eed07acb2057a
#API# API documentation https://drive.google.com/file/d/1KvPbjRVqsgCEzJsUS--zEyxw6cP-pkSI/view
#API#
#API# List all of your cameras, nicely formatted
#API# 
#API# ./reo.sh GetChannelStatus |
#API#   jq -r '.status[] | [.channel,.online,.typeInfo,.name] | @tsv' |
#API#   column -t -s $'\t'
#API# 
#API# Get abilities for currently logged in user
#API# 
#API# ./reo.sh GetAbility '{User:{userName:""}}'
#API# 
#API# Get abilitiies for specific user
#API# 
#API# ./reo.sh GetAbility '{User:{userName:"admin"}}'
#API# 
#API# Some other useful commands
#API# 
#API# ./reo.sh GetDevInfo
#API# ./reo.sh GetDevName
#API# ./reo.sh GetTime
#API# ./reo.sh GetAutoMaint
#API# ./reo.sh GetHddInfo
#API# ./reo.sh GetAutoUpgrade
#API# ./reo.sh GetChannelStatus
#API# ./reo.sh GetUser
#API# ./reo.sh GetOnline
#API# ./reo.sh GetLocalLink
#API# ./reo.sh GetDdns
#API# ./reo.sh GetEmail
#API# ./reo.sh GetFtp
#API# ./reo.sh GetNtp
#API# ./reo.sh GetNetPort
#API# ./reo.sh GetUpnp
#API# ./reo.sh GetWifi
#API#
#API# ./reo.sh GetRtspUrl '{"channel":0}'
#API# ./reo.sh GetPushV20 '{"channel":0}'
#API#  ./reo.sh SetPowerLed '{"PowerLed":{"state":"On","channel":0}}'
#API# ./reo.sh AudioAlarmPlay '{"alarm_mode": "times","manual_switch": 0,"times": 2,"channel": 0}'
#API# ./reo.sh GetIsp # light
#API# ./reo.sh GetMask
#API# ./reo.sh SetMask '{ "Mask":{ "channel":0, "enable":1, "area":[{ "screen":{ "height":720, "width":1280},"block":{ "x":110, "y":95, "width":36, "height":166}},{"screen":{ "height":720, "width":1280},"block":{ "x":251, "y":100, "width":54, "height":175}},{ "screen":{ "height":720, "width":1280},"block":{ "x":425, "y":102, "width":23, "height":211}},{ "screen":{ "height":720, "width":1280},"block":{ "x":632, "y":88, "width":51, "height":245}}]}}'
#API#
#API# ./reo.sh Search '{ "Search": { "channel": 0, "onlyStatus": 0, "streamType": "main", "StartTime": { "year": 2022, "mon": 10, "day": 1, "hour": 0, "min": 0, "sec": 0 }, "EndTime": { "year": 2022, "mon": 11, "day": 1, "hour": 23, "min": 59, "sec": 59 } } }'
#API#
#API# Get/Trigger PTZ Presets
#API# ./reo.sh GetPtzPreset '{channel:0}' { "PtzPreset": [ { "channel": 0, "enable": 1, "id": 0, "imgName": "", "name": "Standard" }, { "channel": 0, "enable": 1, "id": 1, "imgName": "preset_01", "name": "Door" }, { "channel": 0, "enable": 1, "id": 2, "imgName": "preset_02", "name": "Foo" }, ... ... { "channel": 0, "enable": 0, "id": 63, "imgName": "", "name": "pos64" } ] } 
#API# ./reo.sh PtzCtrl '{"channel":0, "op":"ToPos", "id":2, "speed":32}' { "rspCode": 200 }
#API#
#API# Check calibration status, PtzCheckState = 0 --> calibration required, PtzCheckState = 1 --> calibration is running, PtzCheckState = 2 --> calibration done
#API# ./reo.sh GetPtzCheckState
#API# Start calibration
#API# ./reo.sh PtzCheck
#API#
#API#
#API# 3 Commands			 33
#API# 1 System			33
#API# 1.1 GetAbility 			 33
#API# 1.2 GetDevInfo			66
#API# 1.3 GetDevName			 68
#API# 1.4 SetDevName			 69
#API# 1.5 GetTime 			 70
#API# 1.6 SetTime 			 76
#API# 1.7 GetAutoMaint			78
#API# 1.8 SetAutoMaint			80
#API# 1.9 GetHddInfo			 82
#API# 1.10 Format			83
#API# 1.11 Upgrade			 84
#API# 1.12 Restore			86
#API# 1.13 Reboot			 87
#API# 1.14 UpgradePrepare			 88
#API# 1.15 GetAutoUpgrade			89
#API# 1.16 SetAutoUpgrade			 90
#API# 1.17 CheckFirmware			91
#API# 1.18 UpgradeOnline 			92
#API# 1.19 UpgradeStatus			 93
#API# 1.20 Getchannelstatus			95
#API#  Interface Description 			 95
#API# 2 Security 			 98
#API# 2.1 Login			98
#API# 2.2 Logout			 99
#API# 2.3 GetUser			101
#API# 2.4 AddUser			 102
#API# 2.5 DelUser			 104
#API# 2.6 ModifyUser			 105
#API# 2.7 GetOnline 			106
#API# 2.8 Disconnect			 107
#API# 2.9 GetSysCfg			 108
#API# 2.10 SetSysCfg			110
#API#  Interface Description 			 110
#API# 3 Network 			 111
#API# 3.1 GetLocalLink 			111
#API# 3.2 SetLocalLink 			 114
#API# 3.3 GetDdns			 116
#API# 3.4 SetDdns			118
#API# 3.5 GetEmail 			 119
#API# 3.6 SetEmail 			 122
#API# 3.7 GetEmailV20 			 125
#API# 3.8 SetEmailV20 			127
#API# 3.9 TestEmail 			129
#API# 3.10 GetFtp			 131
#API# 3.11 SetFtp			134
#API# 3.12 GetFtpV20			137
#API# 3.13 SetFtpV20			 144
#API# 3.14 TestFtp			 147
#API# 3.15 GetNtp			 149
#API# 3.16 SetNtp			 151
#API# 3.17 GetNetPort			152
#API# 3.18 SetNetPort			 154
#API# 3.19 GetUpnp 			 155
#API# 3.20 SetUpnp 			 156
#API# 3.21 GetWifi 			158
#API# 3.22 SetWifi 			 159
#API# 3.23 TestWifi 			 160
#API# 3.24 ScanWifi 			 162
#API# 3.25 GetWifiSignal 			 163
#API# 3.26 GetPush 			164
#API# 3.27 SetPush 			 166
#API# 3.28 GetPushV20 			 168
#API# 3.29 SetPushV20 			170
#API# 3.30 GetPushCfg			 172
#API# 3.31 SetPushCfg			 173
#API# 3.32 GetP2p			 175
#API# 3.33 SetP2p			176
#API# 3.34 GetCertificateInfo			 177
#API# 3.35 CertificateClear			178
#API# 3.36 GetRtspUrl 			 179
#API#  Interface Description 			 179
#API# 4 Video input			 181
#API# 4.1 GetImage			 181
#API# 4.2 SetImage			 183
#API# 4.3 GetOsd			 184
#API# 4.4 SetOsd			187
#API# 4.5 GetIsp			189
#API# 4.6 SetIsp			 195
#API# 4.7 GetMask 			198
#API# 4.8 SetMask 			 200
#API# 4.9 GetCrop			203
#API# 4.10 SetCrop			 205
#API# 4.11 GetStitch			 207
#API# 4.12 SetStitch			208
#API#  Interface Description 			 208
#API# 5 Enc 			210
#API# 5.1 GetEnc 			210
#API# 5.2 SetEnc 			 216
#API#  Interface Description 			 216
#API# 6 Record			 218
#API# 6.1 GetRec 			218
#API# 6.2 SetRec 			 220
#API# 6.3 GetRecV20 			 222
#API# 6.4 SetRecV20 			225
#API# 6.5 Search			 227
#API# 6.6 Download			232
#API# 6.7 Snap			 233
#API# 6.8 Playback 			 234
#API# 6.9 NvrDownload			235
#API#  Interface Description 			 235
#API# 7 PTZ 			238
#API# 7.1 GetPtzPreset			 238
#API# 7.2 SetPtzPreset			257
#API# 7.3 GetPtzPatrol 			258
#API# 7.4 SetPtzPatrol 			 263
#API# 7.5 PtzCtrl 			 265
#API# 7.6 GetPtzSerial 			 267
#API# 7.7 SetPtzSerial 			 270
#API# 7.8 GetPtzTattern			271
#API# 7.9 SetPtzTattern			 275
#API# 7.10 GetAutoFocus			 277
#API# 7.11 SetAutoFocus			278
#API# 7.12 GetZoomFocus			279
#API# 7.13 StartZoomFocus			280
#API# 7.14 GetPtzGuard			 282
#API# 7.15 SetPtzGuard			283
#API# 7.16 GetPtzCheckState			 284
#API# 7.17 PtzCheck 			 286
#API#  Interface Description 			 286
#API# 8 Alarm			287
#API# 8.1 GetAlarm			287
#API# 8.2 SetAlarm			 296
#API# 8.3 GetMdAlarm			 300
#API# 8.4 SetMdAlarm			314
#API# 8.5 GetMdState			319
#API# 8.6 GetAudioAlarm			320
#API# 8.7 SetAudioAlarm			322
#API# 8.8 GetAudioAlarmV20			324
#API# 8.9 SetAudioAlarmV20 			 327
#API# 8.10 GetBuzzerAlarmV20 			 328
#API# 8.11 SetBuzzerAlarmV20 			 332
#API# 8.12 AudioAlarmPlay 			 333
#API#  Interface Description 			 333
#API# 10 LED			 335
#API# 10.1 GetIrLights			 335
#API# 10.2 SetIrLights			 336
#API# 10.3 GetPowerLed 			 337
#API# 10.4 SetPowerLed 			339
#API# 10.5 GetWhiteLed			340
#API# 10.6 SetWhiteLed			 342
#API# 10.7 GetAiAlarm			 344
#API# 10.8 SetAiAlarm			 347
#API# 10.9 SetAlarmArea 			350
#API#  Interface Description 			 350
#API# 11 AI 			 353
#API# 11.1 GetAiCfg			353
#API# 11.2 SetAiCfg			355
#API# 11.3 GetAiState			356


if [ -z $1 ]; then
	cat $0 | grep -oh "^#API#\(.*\)$" | sed -e "s/^#API#//g"
	exit;
fi

source /etc/reo.conf
HOST=$(grep -F "$MATCH" $IPFILE | grep -oP "$IPREGEX") # "192.168.1.4" # Your NVR or Camera IP Address
if [ -z $HOST ]; then
  # HOST="192.168.1.24"
	>&2 echo "(Sec) Host not found in modem-devices-last.txt . You could try $IPDEFAULT"
  exit 1;
fi
ping -c 1 -W 2 "$HOST" >/dev/null 2>&1 || {
    >&2 echo "Camera offline"
    exit 1
}

URL="https://$HOST/cgi-bin/api.cgi"

# TOKEN must initially be set to null, so that it gets passed to the
# login command as `?cmd=Login&token=null`
TOKEN="null"

# Takes an API command as the first argument, and JSON-ish payload as
# an optional second argument.  If a payload is provided it's
# processed with `jq -n` to make it easier (jq -n doesn't require
# property names to be quoted, you can have trailing commas and other
# stuff that isn't actually valid JSON)
rl-api() {
  local CMD="$1" PARAM='{}'
  if [ -n "$2" ]; then PARAM="$(jq -n "$2")"; fi
  local REQ="$(
    jq -n --arg CMD "$CMD" --argjson PARAM "$PARAM" '{
      cmd: $CMD,
      action: 0,
      param: $PARAM,
    }'
  )"
  local TGT="$URL?cmd=$CMD&token=$TOKEN"
  if $DEBUG; then
    echo ">>> REQUEST >>>" 1>&2
    echo "TARGET: $TGT" 1>&2
    jq -C . <<<"$REQ" 1>&2
  fi
  local RES="$(
    curl -kfsSLH 'Content-Type: application/json' -d "[$REQ]" -XPOST "$TGT"  |
      jq '.[0]'
  )"
	if [ -z "$RES" ]; then
		exit 1;
	fi

  if $DEBUG; then
    echo "<<< RESPONSE <<<" 1>&2
    jq -C . <<<"$RES" 1>&2
  fi
  # If the response had "code: 0" then it was successful, otherwise it
  # was an error
  if [ "$(jq -r '.code' <<<"$RES")" -eq "0" ]; then
    jq '.value' <<<"$RES"
    return 0
  else
    echo -n "$CMD ERROR: " 1>&2
    jq -r '"\(.error.detail) (\(.error.rspCode))"' <<< "$RES" 1>&2
    return 1
  fi
}
# Send a Login command to the API
rl-login() {
  rl-api Login "$(
    jq -n --arg USER "$USER" --arg PASS "$PASS" '{
      User: { userName: $USER, password: $PASS }
    }'
  )" | jq -r '.Token.name'
}
# Send a Logout command to the API
rl-logout() {
  if [ "$TOKEN" = "null" ] || [ "$TOKEN" = "" ]; then return; fi
  rl-api Logout > /dev/null
}

# Login with username and password and get a session token
TOKEN="$(rl-login)"
if [ -z "$TOKEN" ]; then exit 1; fi

# Now that we have a token, we add an exit hook to remove it when the
# script exits, if you leave it around you may get the dreaded (and
# annoying) "max session" error.  If that happens all you can really
# do is wait, by default the tokens are good for an hour (and the
# session limit is global, so using multiple usernames won't help)
trap 'rl-logout' EXIT

# Process any arguments on the command line as commands, if the
# command is followed by something that looks like a payload, then
# pass that as the payload to the command.
while (( $# )); do
  CMD="$1" ; shift
  #if (( $# )) && jq -eR 'try(fromjson)' <<<"$1"; then
  if (( $# )) && [[ $1 == *[{}]* ]]; then
    PAYLOAD="$1" ; shift
  else
    PAYLOAD="{}"
  fi
  rl-api "$CMD" "$PAYLOAD" || exit 1
done

