#!/usr/bin/perl -w

use strict;
use Net::SSH2 qw(LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
                 LIBSSH2_CHANNEL_FLUSH_ALL
                 LIBSSH2_HOSTKEY_POLICY_ASK);
use JSON::XS;
use Data::Dumper;
use Hash::Merge::Simple qw/ merge /;
use Digest::SHA qw(sha256_hex);
use Encode qw( decode );
use Getopt::Long::Descriptive;
use Tie::IxHash;
my $lockfile = '/tmp/ac68u.lock';
my $locktimeout = 10;
$| = 1;

# from https://metacpan.org/dist/Regexp-IPv4/source/lib/Regexp/IPv4.pm
my $dig_re = '(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})';
my $ipv4_regex = "(?:$dig_re(?:\\.$dig_re){3})";
my $ipv6_regex = "(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{0,4}|(?:[0-9A-Fa-f]{1,4}:)*:[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])";	# not tested very well
my $mac_regex = "(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})";

my ($opt, $usage) = describe_options(
  qq|This program will access an ASUS AC68U DSL modem over SSH and get or change settings from commandline.

Usage: $0 \%o
Example 1: $0 -h 192.168.1.254 -p "secret" -s openvpn
Example 2: $0 -h 192.168.1.254 -p "secret" -s openvpn --target 192.168.1.6
Example 3: $0 -h 192.168.1.254 -p "secret" -s openvpn --close
Example 4: $0 -h 192.168.1.254 -p "secret" --ip
Example 5: $0 -h 192.168.1.254 -p "secret" --reboot
Example 6: $0 -h 192.168.1.254 -p "secret" --wifi
Example 7: $0 -h 192.168.1.254 -p "secret" --devices
Example 8: $0 -h 192.168.1.254 -p "secret" --status

WARNING: If your login failed to many times your access will be disabled for a while.

	|,

	[ 'host|h=s',			"Modem ip", { required => 1, default => '192.168.1.254' } ],
	[ 'username|u=s',	"Username", { required => 1, default => 'Admin' } ],
	[ 'password|p=s',	"Password or set your password through environment variable PASSWORD", { callbacks =>  {
		'Give password as argument or via environment as password or PASSWORD' => sub { defined $_[1]->{'password'} || $ENV{'password'} || $ENV{'PASSWORD'} },
	} } ],
	[ 'force|f',		"Not supported on this modem, here for compatibility with h369a script" ],
	[ 'ip',					"Get WAN IP address" ],
	[ 'reboot|r',		"Reboot modem" ],
#	[ 'sleep',			"Seconds to sleep when another user is logged in and try again" ],	# not supported yet
	[ 'service|s=s',	"Get or change service" ],
	[ 'port=i',			"LAN port number to get or set instead of service"  ],	# TODO: allow to set multiple ports (i.e. 22,23) or range (i.e. 22:26)
	[ 'wanport=i',	"WAN port number to get or set instead of service"  ],
	[ 'close',			"Delete forwarding", { callbacks => { 
		'Specify port or service' => sub {  defined $_[1]->{'service'} || defined $_[1]->{'port'}  },
	} } ],
	[ 'source=s',		"Accept connection from ip", { callbacks => {	# implies is broken but still used for validation
		'Valid ipv4' => sub { $_[0] =~ /^$ipv4_regex$/ },
		'Specify port or service' => sub {  defined $_[1]->{'service'} || defined $_[1]->{'port'}  },
	} } ],
	[ 'target|t=s', "Forward service to ip", { callbacks => {	# implies is broken but still used for validation
		'Valid ipv4' => sub { $_[0] =~ /^$ipv4_regex$/ },
		'Specify port or service' => sub {  defined $_[1]->{'service'} || defined $_[1]->{'port'}  },
	} } ],
	[ 'wifi|w',"List wifi devices" ],
	[ 'devices|d',"List devices" ],
	[ 'countrycode|c=s',	"Set wifi country code. WARNING: Setting an invalid country code could result in illegal values"],
	[ 'status', "Get status for interfaces" ],
	[ 'exec=s', "For development" ],
	[],
	[ 'verbose|v',  "print extra stuff" ],
	[ 'help',       "print usage message and exit", { shortcircuit => 1 } ],
);

lockfile();
init($opt);

sub init {
	my $opt = $_[0] || die('Expected options');
	my $password = $opt->password || $ENV{'password'} || $ENV{'PASSWORD'};
	warn "Password not given" if !$password;
	print($usage->text), exit if $opt->help || !$password || (!$opt->ip && !$opt->reboot && !$opt->service && !$opt->port && !$opt->wifi && !$opt->devices && !$opt->status && !$opt->verbose && !$opt->countrycode && !$opt->exec);

	warn("Force ignored, not supported") if $opt->force;

	my $ua = Net::SSH2->new();
	my $response = login($ua, $opt->host, $opt->username, $password);

	if ($opt->reboot) {
		print reboot($ua, $opt->host), "\n";
	}

	if ($opt->wifi) {
		my @devices = map { $_->{'wireless'} && $_->{'connected'} && !$_->{'local'} ? $_ : ()  } @{getNetworkDevices($ua)};
		printf("%15s %40s %30s %18s %s\n", "IPv4", "Host (Alias)", "Vendor", "MAC", "Interface");
		foreach my $device (@devices) {
			printf("%15s %40s %30s %18s %s\n", $device->{'ipv4'} || '', ($device->{'host'} || '').($device->{'name'} ? ' ('.$device->{'name'}.')' : ''), substr($device->{'vendor'}||'', 0, 30), $device->{'mac'} || '', ($device->{'interface'}||''));
		}
	}

	if ($opt->devices) {
		my @devices = map { $_->{'connected'} && !$_->{'local'} ? $_ : ()  } @{getNetworkDevices($ua)};
		printf("%15s %40s %30s %18s %s\n", "IPv4", "Host (Alias)", "Vendor", "MAC", "Interface");
		foreach my $device (@devices) {
			printf("%15s %40s %30s %18s %s\n", $device->{'ipv4'} || '', ($device->{'host'} || '').($device->{'name'} ? ' ('.$device->{'name'}.')' : ''), substr($device->{'vendor'}||'', 0, 30), $device->{'mac'} || '', ($device->{'interface'}||''));
		}
	}

	if ($opt->status) {
		my %status = (
#			'wlan' => getWlanStatus($ua, $opt->host),
#			'wlanguest' => getWlanGuestStatus($ua, $opt->host),
#			'lan' => getLanStatus($ua, $opt->host),
		);
		print Dumper \%status;
	}

	if ($opt->ip) {
		print getIp($ua, $opt->host), "\n";
	}

	if ($opt->countrycode) {
		print Dumper setWifiCountry($ua, $opt->countrycode);
	}

	if ($opt->exec) {
		setAllowLoginAfterLogout($ua);
		my $result = execute($ua, $opt->exec);
		print $result, "\n";
	}

	if ($opt->service || $opt->port) {
		my $lan_port = $opt->port || getPortFromService($opt->service) || '';
		if ($lan_port) {
			my @rules = getPortForwardingRule($ua, $lan_port, $opt->target, $opt->source, $opt->wanport);

			if ($opt->target && !$opt->close) {
				if (@rules) {
					warn("Skipped: Port forward to port ".$opt->target.":$lan_port already exists. Create manually.");
				} else {
					@rules = @rules = addPortForwardingRule($ua, {
						'name' => $opt->port ? $opt->service : '',	# if port was not set the port was resolved from service and service name is generated
						'wan_port' => $opt->wanport || $opt->port,
						'lan_ip' => $opt->target,
						'lan_port' => $lan_port,
						'protocol' => 'TCP',
						'source_ip' => $opt->source,
					});
				}
			}

			if ($opt->close) {
				if (@rules) {
					@rules = closePortForwardingRule($ua, $lan_port, $opt->target, $opt->source, $opt->wanport);
				} else {
					warn("Could not close non-existing forward to port ".($opt->target||'').":$lan_port");
				}
			}

			print Dumper \@rules;
		} else {
			warn("WAN port $lan_port not found");
		}
	}
	logout($ua, $opt->host);
}

END {
	unlock();
}

sub unlock {
  unlink $lockfile if -e $lockfile && do { open my $fh, '<', $lockfile; chomp(my $x = <$fh>); $x } == $$;
}

sub lockfile {
	while($locktimeout-->0 && -e $lockfile) {
		sleep 1;
	}
	open(my $fh, '>', $lockfile) or die $!; print $fh $$; close $fh;
	$SIG{TERM} = $SIG{INT} = sub {
		unlock();
	};

}

sub login {
	my ($ssh2, $host, $username, $password) = @_;
	$ssh2->timeout(4*1000);
	print "Connecting...\n" if $opt->verbose;
	$ssh2->connect($host) or $ssh2->die_with_error;;
	$ssh2->timeout(20*1000);
	print "Authorizing...\n" if $opt->verbose;
	# TODO: support $ssh2->auth_publickey ( username, publickey_path, privatekey_path [, passphrase ] );
	# TODO: implement passwordCallback for expired passwords getPassword($self, $username)
	my $getPasswordRef = undef;
	$ssh2->auth_password ( $username, $password ) or $ssh2->die_with_error;
	print "Logged in\n" if $opt->verbose;
	return $ssh2;
}

sub logout {
	my ($ssh2, $host) = @_;
	print "Disconnecting...\n" if $opt->verbose;
	$ssh2->disconnect;
	print "Disconnected\n" if $opt->verbose;
#	return $status;
}

sub trim { local $_ = shift; s/^\s+|\s+$//gr }

# WARN: NEVER allow user input since they can inject commands
sub execute {
	my ($ssh2, $cmds) = @_;
	$cmds = [$cmds] if ref $cmds ne 'ARRAY';
	my @results = ();
	foreach my $cmd (@$cmds) {
		print "Executing command \"$cmd\"...\n" if $opt->verbose;
		my $chan = $ssh2->channel;
		$chan->exec($cmd) or $ssh2->die_with_error;
		print "Send\n" if $opt->verbose;
		print "Reading output...\n" if $opt->verbose;
		$chan->ext_data(LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);
		# my $result = do { local $/; <$chan>;	};	# $/ = read all at once
		my @result = <$chan>;
		$chan->send_eof;
		$chan->close;
		$chan->wait_closed;
		print @result if $opt->verbose;
		push @results, \@result;
	}
	print "Finished\n" if $opt->verbose;
	return wantarray ? @results : trim(join("\n", map @$_, @results));
}

sub isRuleMatch {
	my ($lan_port, $lan_ip, $source_ip, $wan_port) = @_;
	return (
			($_->{'lan_port'} && $_->{'lan_port'} eq $lan_port)
			|| (!$_->{'lan_port'} && $_->{'wan_port'} eq $lan_port)
		)
		&& (!$lan_ip || $_->{'lan_ip'} eq $lan_ip)
		&& (!$source_ip || $_->{'source_ip'} eq $source_ip)
		&& (!$wan_port || $_->{'wan_port'} eq $wan_port);
}

sub getPortFromService {
	my $service = $_[0] || return("getPortFromService: Expected service");
	print "Getting port from service $service..." if $opt->verbose;
	my $port = (getservbyname($service, 'tcp'))[2];
	$port = (getservbyname($service, 'udp'))[2] if !$port;
	warn("Service $service has no known port") if !$port;
	return $port;
}

sub getServiceFromPort {
	my $port = $_[0] || return("getPortFromService: Expected port");
	print "Getting service from port $port..." if $opt->verbose;
	my @service = getservbyport($port, 'tcp');
	@service = getservbyport($port, 'udp') if !@service;
	if (!@service) {
		warn("Port $port has no known service, generating name based on port number");
		@service = ( $port, undef, $port, 'TCP' );
	}
	return wantarray ? ($service[0], $service[3]) : $service[0];
}

sub getPortForwardingRules {
	my ($ssh2) = @_;
	print "Getting port forwarding rules..." if $opt->verbose;
	my $rulesString = execute($ssh2, 'nvram get vts_rulelist');
	# '<IMAP>143,993>192.168.2.6>>TCP><HTTPS>443>192.168.2.6>>TCP><SMTP>25,465,587>192.168.2.6>>TCP><Soulseek>55219:55220>192.168.2.42>>TCP><ssh>8222>192.168.2.6>22>TCP>1.1.1.1

	my @rules = ();
	while ($rulesString =~ /<([^>]+)>([^<]*)/g) {
			my ($name, $rest) = ($1, $2);
			my ($wan_port, $lan_ip, $lan_port, $proto, $src_ip) = split />/, $rest, 5;
			push @rules, {
					name      => $name,
					wan_port  => $wan_port,
					lan_ip    => $lan_ip,
					lan_port  => length($lan_port) ? $lan_port : undef,
					protocol  => $proto,
					source_ip => length($src_ip) ? $src_ip : undef,
			};
	}
	return @rules;
}

sub getPortForwardingRule {
	my ($ssh2, $lan_port, $lan_ip, $source_ip, $wan_port) = @_;
	print "Getting port forwarding rule for LAN port $lan_port..." if $opt->verbose;
	my @rules = getPortForwardingRules($ssh2);
	@rules = map { isRuleMatch($lan_port, $lan_ip, $source_ip, $wan_port) ? $_ : () } @rules;
	return wantarray ? @rules : pop @rules;
}

sub setPortForwardingRules {
	my ($ssh2, $rules) = @_;
	map {
		$_->{'wan_port'} = $_->{'lan_port'} if $_->{'lan_port'} && !$_->{'wan_port'};
		if (!$_->{'name'} || !$_->{'protocol'}) {
			my $firstPort = ($_->{lan_port} || $_->{wan_port}) =~ /^(\d+)/ ? $1 : die('Invalid port');
			my ($name, $protocol) = getServiceFromPort($firstPort);
 			if (!$_->{'name'}) {
				$_->{'name'} = $_->{'source_ip'} ? $name.' from '.$_->{'source_ip'} : $name.' to '.$_->{'lan_ip'};
			}
			$_->{'protocol'} = $protocol if $_->{'protocol'};
		}
	} @$rules;
	my @errors = map {
		length $_->{'name'} > 30 ? "Service name ".$_->{'name'}." exceeds maximum length of 30 characters" :
		$_->{'name'} =~ /([<>'%])/ ? "Service name contains reserved characters $1" :
		!$_->{'lan_port'} && !$_->{'wan_port'} ? 'Wan port is required' :
		!$_->{'lan_ip'} ? 'Target IP is required' :
		!$_->{'protocol'} ? 'Protocol is required' :
		();
	} @$rules;
	print "\n\n\n";
	my %seen_name = ();
	push @errors, "Port forwarding rule names not unique. Add rule manually." if (grep { $seen_name{lc $_->{'name'}}++ } @$rules);
	my %seen_wan_port = ();
	push @errors, "Port forwarding WAN + source_ip port must be unique." if (grep { $seen_wan_port{ $_->{'wan_port'}.' '.($_->{'source_ip'}||'') }++ } @$rules);
	if (@errors) {
		warn @errors;
	} else {
		my $rulesString = join '', map {
			sprintf '<%s>%s>%s>%s>%s>%s',
				$_->{'name'},
				ref $_->{'wan_port'} eq 'ARRAY' ? join(',', @{ $_->{wan_port} }) : $_->{wan_port},
				$_->{'lan_ip'} || '',
				$_->{'lan_port'} && $_->{'lan_port'} eq $_->{'wan_port'} ? '' : $_->{'lan_port'} || '',
				uc($_->{'protocol'}),
				$_->{'source_ip'} || '',
		} @$rules;
		die("Rules invalid, containing reserved characters") if $rulesString =~ /['"]/;
		my $out = execute($ssh2, "nvram set vts_rulelist='$rulesString'; nvram commit; /sbin/service restart_firewall");
		print $out;
		return $rulesString;
	}
}

sub addPortForwardingRule {
	my ($ssh2, $rule) = @_;
	print "Adding port forwarding rule ", $rule->{'source_ip'}||"*", ":", $rule->{'wan_port'}||$rule->{'lan_port'}, " to $rule->{'lan_ip'}:$rule->{'lan_port'}\n";
	my @rules = getPortForwardingRules($ssh2);
	push @rules, $rule;
	setPortForwardingRules($ssh2, \@rules);
	return getPortForwardingRule($ssh2, $rule->{'lan_port'}, $rule->{'lan_ip'}, $rule->{'source_ip'}, $rule->{'wan_port'});
}

sub closePortForwardingRule {
	my ($ssh2, $lan_port, $lan_ip, $source_ip, $wan_port) = @_;
	my @rules = getPortForwardingRules($ssh2);
	my @existingRules = map { isRuleMatch($lan_port, $lan_ip, $source_ip, $wan_port) ? $_ : () } @rules;
	foreach my $rule (@existingRules) {
		print "Closing port forwarding rule ", $rule->{'source_ip'}||"*", ":", $rule->{'wan_port'}||$rule->{'lan_port'}, " to $rule->{'lan_ip'}:$rule->{'lan_port'}\n";
	}
	@rules = map { isRuleMatch($lan_port, $lan_ip, $source_ip, $wan_port) ? () : $_ } @rules;
	setPortForwardingRules($ssh2, \@rules);
	return @existingRules;
}

sub reboot {
	my ($ssh2) = @_;
	print "Rebooting...\n" if $opt->verbose;
	my $out = execute($ssh2, 'reboot');
	return $out;
}

sub getIp {
	my ($ssh2) = @_;
	print "Get IP...\n" if $opt->verbose;
	my $out = execute($ssh2, 'nvram get dsl_ipaddr');
	return ($out =~ /\b($ipv4_regex)\b/) && $1 ne '0.0.0.0' ? $1 : die('Error: ', $out);
}

sub setWifiCountry {
	my ($ssh2, $country_code) = @_;
	# key line is nvram set asuscfecommit=1 — that's the flag that tells the firmware to actually push the asuscfeX:ccode values into the CFE partition on this commit/reboot cycle
	# instead of writing to regular nvram image that gets overridden at boot.
	die "Invalid country code $country_code" if $country_code !~ /^[A-Z]{2}$/;
	my $command = qq|
		wl -i eth1 country $country_code &&
		wl -i eth2 country $country_code &&
		nvram set asuscfe0:ccode=$country_code &&
		nvram set asuscfe1:ccode=$country_code &&
		nvram set asuscfe0:regrev=0 &&
		nvram set asuscfe1:regrev=0 &&
		nvram set asuscfecommit=1 &&
		nvram set 0:regrev=0 &&
		nvram set 1:regrev=0 &&
		nvram set 0:ccode=$country_code &&
		nvram set 1:ccode=$country_code &&
		nvram set pci/1/1/ccode=$country_code &&
		nvram set pci/1/1/regrev=0 &&
		nvram set pci/2/1/ccode=$country_code &&
		nvram set pci/2/1/regrev=0 &&
		nvram set regulation_domain=$country_code &&
		nvram set regulation_domain_5G=$country_code &&
		nvram set wl_country_code=$country_code &&
		nvram set wl_country_rev=0 &&
		nvram set wl0_country=$country_code &&
		nvram set wl0_country_code=$country_code &&
		nvram set wl0_country_rev=0 &&
		nvram set wl0_reg_mode=off &&
		nvram set wl1_country=$country_code &&
		nvram set wl1_country_code=$country_code &&
		nvram set wl1_country_rev=0 &&
		nvram set wl1_reg_mode=off &&
		nvram commit &&
		service restart_network &&
		wl -i eth1 txpwr &&
		wl -i eth1 txpwr_target_max &&
		wl -i eth1 country &&
		wl -i eth2 txpwr &&
		wl -i eth2 txpwr_target_max &&
		wl -i eth2 country
	|;
	print $command;
	my $res = execute($ssh2, $command);
	return $res;
}

sub getNetworkDevices {
  my ($ssh2) = @_;
  print "Fetching device list...\n" if $opt->verbose;
  my $bridges = execute($ssh2, 'brctl show | grep -o "^br\S*" | grep -v bridge');
	my %connections = ();

	# cached by bridge
	foreach my $bridge (split /[\n\r]+/, $bridges) {
		print "Getting connections to bridge $bridge...\n" if $opt->verbose;
		my ($interfaces_lines, $connections_lines) = execute($ssh2, ['brctl showstp '.$bridge.' | grep -o "^\S.*)"', "brctl showmacs $bridge"]);
		my %interfaces = map { $_ =~ /^(\S+).*\((\d+)\)/  ? ($2 => $1) : ()  } @$interfaces_lines;
		map { $_ =~ /^\s*(\d+)\s+($mac_regex)\s+(\w+)\s+([\d\.]+)/ ? !$connections{lc $2}->{'local'} ? $connections{lc $2} = {
			'connected' => 1,
			'interface' => $interfaces{$1},
			'mac' => $2,
			'local' => $3 eq 'yes' ? 1 : 0,
			'age' => $4,
		} : () : () } @$connections_lines;
		# print Dumper \%connections;
	}

	# scan connected wireless devices
	my ($wirelessInterfacesLines, $ssidLines, $portLines) = execute($ssh2, ['nvram show 2>/dev/null | grep -E "^wl_ifnames|_vifs"', 'nvram show | grep -iE "_ifname=eth|_ssid=" | sort', 'robocfg show|grep Port']);

	foreach my $line (@$portLines) {
		if ($line =~ /^Port\s*(\d+)\W*(\S*).*\b($mac_regex)\b/) {
			my ($mac, $status, $port) = (lc $3, $2, 'LAN'.$1);
			if (!$connections{$mac} || $status ne 'DOWN') {	# if it is disconnected and not reconnected, register latest known
				$connections{$mac}->{'mac'} = $mac;
				$connections{$mac}->{'interface'} = $port;
				$connections{$mac}->{'connected'} = $status ne 'DOWN';
			}
		}
	}

	my %ssids = ();
	my %ifMap = ();
	foreach my $line (@$ssidLines) {
		$ifMap{$1} = $2 if $line =~ /(\S*)_ifname=(\S*)/;
		if ($line =~ /(\S*)_ssid=(.*)/) {
			$ssids{$1} = $2;
			$ssids{ $ifMap{$1} } = $2 if $ifMap{$1};
		}
	}
	my %wirelessInterfaces = ();
	foreach my $wirelessInterfacesLine (@$wirelessInterfacesLines) {
		$wirelessInterfacesLine =~ s/^.*?=//;
		%wirelessInterfaces = (%wirelessInterfaces, map { $_ => $_ } split(/\s/, $wirelessInterfacesLine));
	}
	foreach my $wirelessInterface (keys %wirelessInterfaces) {
		my ($connections_lines) = execute($ssh2, "wl -i $wirelessInterface assoclist");
		map { $_ =~ /\b($mac_regex)\b/ ? $connections{lc $1} = {
			'connected' => 1,
			'interface' => $ssids{$wirelessInterface} || $wirelessInterface,
			'wireless' => 1,
		} : () } @$connections_lines;
	}


	# local mac adresses
	my ($localNetworkDevices) = execute($ssh2, 'ifconfig -a | grep "^\S"');
	foreach my $localNetworkDevice (@$localNetworkDevices) {
		($connections{$2}->{'local'} = 1 && $connections{$2}->{'mac'} = $2) if ($localNetworkDevice =~ /^(\S+).*?($mac_regex)/);
	}

  my ($client_list_lines, $json, $dnsmasq_lines, $ip_neigh_lines) = execute($ssh2, ['nvram get custom_clientlist', 'cat /jffs/nmp_cl_json.js', 'cat /var/lib/misc/dnsmasq.leases', 'ip neigh show']);
	# Refresh ARP: "ping -c1 -w1 192.168.2.142; arp -a"

	# ARP table MAC <=> IP + hostname	# arp -a
#	foreach my $line (@$arp_devices) {
#		my $mac = $line =~ /\b($mac_regex)\b/ ? $1 : '';
#		if ($mac) {
#			if (my $connection = $connections{lc $mac}) {
#				$connection->{'name'} = $1 if !$connection->{'name'} && $line =~ /^(.*?)\.?\s/ && $1 ne '?';
#				$connection->{'ipv4'} = $1 if !$connection->{'ipv4'} && $line =~ /\b($ipv4_regex)\b/;
#				$connection->{'ipv6'} = $1 if !$connection->{'ipv6'} && $line =~ /\b($ipv6_regex)\b/ && $1 ne $mac;
#				$connection->{'interface'} = $1 if !$connection->{'interface'} && $line =~ /(\S+)$/;
#			} else {
#				warn "Could not find ARP $mac in connection list: $line";
#			}
#		}
#	}

	# hostname, mac, group, type, callback, keeparp
	# icon for type number in device-map.css:180
	my $client_list = join('', @$client_list_lines);
	while ($client_list =~ /<([^>]+)>([^<]*)/g) {
			my ($host, $rest) = ($1, $2);
			my ($mac, $group, $type, $callback, $keeparp) = split />/, $rest, 5;
			$connections{lc $mac}->{'host'} = $host;
	}

	# jffs network map client?
	my $coder = JSON::XS->new->ascii->pretty->allow_nonref;
	my $devices = $coder->decode(join("\n", @$json));
	%$devices = map { lc($_) => $devices->{$_} } keys %$devices;	# make keys lower case

	# DNS masq leases: 'cat /var/lib/misc/dnsmasq.leases'
	foreach my $line (@$dnsmasq_lines) {
		my($expire, $mac, $ip, $alias, $id) = split /\s+/, $line;
		if (my $device = $devices->{lc $mac}) {
			$device->{'expire'} = $expire if !$device->{'expire'} && $expire;
			$device->{'name'} = $alias if !$device->{'name'} && $alias;
			$device->{'id'} = $id if !$device->{'id'} && $id;
			$device->{'ipv4'} = $1 if !$device->{'ipv4'} && $ip =~ /\b($ipv4_regex)\b/;
			$device->{'ipv6'} = $1 if !$device->{'ipv6'} && $ip =~ /\b($ipv6_regex)\b/ && $ip ne $mac;
		} else {
			warn "Could not find dnsmasq $mac in device list: $line";
		}
	}

	# ip neigh ARP table MAC <=> IP + state
	foreach my $line (@$ip_neigh_lines) {
		my %disconnectedStates = (
			# 'STALE' => 1,	# may be old though
			# 'INCOMPLETE' => 1,	only shortly INCOMPLETE, so was very recently connected
			'FAILED' => 1,
			'PROBE' => 1,	# actively checked, not STALE anymore
			
		);
		my $mac = $line =~ /\b($mac_regex)\b/ ? $1 : '';
		# print "TEST $mac ", Dumper $devices->{lc $mac};
		if ($mac) {
			my $device = $devices->{lc $mac};
			$device->{lc $mac} = {} if !$device;
			$device->{'ipv4'} = $1 if !$device->{'ipv4'} && $line =~ /\b($ipv4_regex)\b/;
			$device->{'ipv6'} = $1 if !$device->{'ipv6'} && $line =~ /\b($ipv6_regex)\b/ && $1 ne $mac;
			$device->{'interface'} = $1 if !$device->{'interface'} && $line =~ /\s+dev\s+(\S*)/;	# br0
			$device->{'state'} = $1 if !$device->{'state'} && $line =~ /\slladdr\s+\S*\s+(\S*)/;
			$device->{'connected'} = 1 if !$disconnectedStates{ $device->{'state'} }; 
			# print Dumper $device;
		}
	}

	# MAC table (not used because of bigger delay after disconnect)
	# robocfg showmacs

	
	my $result = merge $devices, \%connections;
	my @out = sort { $a->{'mac'} cmp $b->{'mac'} } values %$result;
	map { $_->{'mac'} = lc $_->{'mac'}; $_->{'interface'} && $wirelessInterfaces{$_->{'interface'}} ? $_->{'wireless'} = 1 : () } @out;
	# print Dumper \@out;
  return \@out;
}

sub setAllowLoginAfterLogout {
	my ($ssh2) = @_;
	my $out = execute($ssh2, qq|
		umount /www/Main_Login.asp \|\| 
		cp /www/Main_Login.asp /tmp/Main_Login.asp &&
		mount --bind /tmp/Main_Login.asp /www/Main_Login.asp &&
		sed -i 's/document\\.getElementById("login_filed")\\.style\\.display ="none";/\\/\\/document.getElementById("login_filed").style.display ="none";/' /tmp/Main_Login.asp
	|);
	print Dumper $out;
	return Dumper $out;
}

