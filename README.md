# h369a
This program will access an Experia box v10 H369A DSL modem over http and get or change settings from commandline.

Introduction
------------
I wrote a Experia box v10 H369AExperia box v10 H369A DSL modem commandline client for easier management.

Currently it supports:
- Forward NAT ports to IP address
- Close NAT ports
- Get external IP address from modem

I wrote this code for my own use so it is not tested except for my own current modem.

Tested on:

        Hardware Version V1.00
        Software Version V1.01.00T04.0
        Boot Loader Version V1.0.00 

Usage
-----
Usage: ./h369a.pl [-fhpstuv] [long options...]

				Example 1: ./h369a.pl -h 192.168.1.254 -p "secret" -s openvpn
				Example 2: ./h369a.pl -h 192.168.1.254 -p "secret" -s openvpn --target 192.168.1.6
				Example 3: ./h369a.pl -h 192.168.1.254 -p "secret" -s openvpn --close
				Example 4: ./h369a.pl -h 192.168.1.254 -p "secret" --ip

To open specific ports create services with port mappings manually under Settings > Port Forwarding - IPv4 > Application Configuration > Create New App Name

Options
-------
Run the program without arguments to get a list of options

        -h STR --host STR      Modem ip
        -u STR --username STR  Username
        -p STR --password STR  Password
        -f --force             Force another user to logout
        --ip                   Get WAN IP address
        -s STR --service STR   Get or change service
        --port INT             Port number to get or set instead of service
                               (TODO: create a service if it does not exist)
        --close                Delete forwarding
        -t STR --target STR    Forward service to ip

        -v --verbose           print extra stuff
        --help                 print usage message and exit

Known issues
------------
WARNING: If your login failed to many times your access will be disabled for a while.

Credits
-------
- Author: Gerben Versluis
- Distributed under GNU General Public License v3.0
