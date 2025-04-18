#!/usr/bin/perl -w

use strict;
use LWP::UserAgent;
use Data::Dumper;
use Digest::SHA qw(sha256_hex);
use Encode qw( decode );
use Getopt::Long::Descriptive;
use Tie::IxHash;
use XML::Simple;
my $lockfile = '/tmp/h369a.lock';
my $locktimeout = 10;
$| = 1;


my ($opt, $usage) = describe_options(
  qq|This program will access a Experia box v10 H369A DSL modem over http and get or change settings from commandline.

Usage: $0 \%o
Example 1: $0 -h 192.168.1.254 -p "secret" -s openvpn
Example 2: $0 -h 192.168.1.254 -p "secret" -s openvpn --target 192.168.1.6
Example 3: $0 -h 192.168.1.254 -p "secret" -s openvpn --close
Example 4: $0 -h 192.168.1.254 -p "secret" --ip
Example 5: $0 -h 192.168.1.254 -p "secret" --wifi
Example 6: $0 -h 192.168.1.254 -p "secret" --devices
Example 7: $0 -h 192.168.1.254 -p "secret" --status

To open specific ports create services with port mappings manually under Settings > Port Forwarding - IPv4 > Application Configuration > Create New App Name

WARNING: If your login failed to many times your access will be disabled for a while.

	|,

	[ 'host|h=s',		"Modem ip", { required => 1, default => '192.168.1.254' } ],
	[ 'username|u=s',	"Username", { required => 1, default => 'Admin' } ],
	[ 'password|p=s',	"Password", { callbacks =>  {
		'Give password as argument or via environment as password or PASSWORD' => sub { defined $_[1]->{'password'} || $ENV{'password'} || $ENV{'PASSWORD'} },
	} } ],
	[ 'force|f',		"Force another user to logout" ],
	[ 'ip',				"Get WAN IP address" ],
#	[ 'sleep',			"Seconds to sleep when another user is logged in and try again" ],	# not supported yet
	[ 'service|s=s',	"Get or change service", { callbacks => { 
		'Specify either port OR service' => sub {  !defined $_[1]->{'port'}  },
	} } ],
	[ 'port=i',			"Port number to get or set instead of service (TODO: create a service if it does not exist)"  ],
	[ 'close',			"Delete forwarding", { callbacks => { 
		'Specify port or service' => sub {  defined $_[1]->{'service'} || defined $_[1]->{'port'}  },
	} } ],
	[ 'target|t=s', "Forward service to ip", { callbacks => {	# implies is broken but still used for validation
		'Valid ipv4' => sub { $_[0] =~ /^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/ },
		'Specify port or service' => sub {  defined $_[1]->{'service'} || defined $_[1]->{'port'}  },
	} } ],
	[ 'wifi|w',"List wifi devices" ],
	[ 'devices|d',"List devices" ],
	[ 'status', "Get status for interfaces" ],
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
	print($usage->text), exit if $opt->help || !$password;

	my $ua = LWP::UserAgent->new( max_redirect => 2, requests_redirectable => ['GET', 'POST', 'HEAD'] );
	$ua->agent('Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0');	# not required... yet
	$ua->show_progress(1) if $opt->verbose;
	$ua->cookie_jar( {} );

	my $response = login($ua, $opt->host, $opt->username, $password, $opt->force);
	if ($opt->wifi) {
		my @devices = ();
		push @devices, @{getWlanDevices($ua, $opt->host)};
		push @devices, @{getWlanGuestDevices($ua, $opt->host)};
		printf("%15s %40s %23s %s\n", "IPv4", "Host (Alias)", "MAC", "Interface");
		foreach my $device (@devices) {
			printf("%15s %40s %23s %s\n", $device->{'IPAddress'}, (ref($device->{'HostName'}) eq 'HASH'?'':$device->{'HostName'}).' '.(ref($device->{'AliasName'}) eq 'HASH'?'':'('.$device->{'AliasName'}.')'), $device->{'MACAddress'}, $device->{'Port'});
		}
	}

	if ($opt->devices) {
		my @devices = ();
		push @devices, @{getWlanDevices($ua, $opt->host)};
		push @devices, @{getWlanGuestDevices($ua, $opt->host)};
		push @devices, @{getLanDevices($ua, $opt->host)};
		printf("%15s %40s %23s %s\n", "IPv4", "Host (Alias)", "MAC", "Interface");
		foreach my $device (@devices) {
			printf("%15s %40s %23s %s\n", $device->{'IPAddress'}, (ref($device->{'HostName'}) eq 'HASH'?'':$device->{'HostName'}).' '.(ref($device->{'AliasName'}) eq 'HASH'?'':'('.$device->{'AliasName'}.')'), $device->{'MACAddress'}, $device->{'Port'});
		}
	}

	if ($opt->status) {
		my %status = (
			'wlan' => getWlanStatus($ua, $opt->host),
			'wlanguest' => getWlanGuestStatus($ua, $opt->host),
			'lan' => getLanStatus($ua, $opt->host),
		);
		print Dumper \%status;
	}

	if ($opt->ip) {
		print getIp($ua, $opt->host), "\n" if $opt->ip;
	}

	my $service = $opt->service || undef;
	$service = getPortService($ua, $opt->host, $opt->port) if ($opt->port);

	if ($service) {
		print Dumper addService($ua, $opt->host, $service, $opt->target) if $opt->target;
		print Dumper deleteService($ua, $opt->host, $service) if $opt->close;
		if (!$opt->target && !$opt->close) {
			my $serviceDetails = getService($ua, $opt->host, $service) || die('Service not found: '.$service);
			print Dumper $serviceDetails;
			print Dumper getPortMapping($ua, $opt->host, $service);
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

sub getUnique {
	return time();
}

sub instanceToSet {
	my $instance = ref $_[0] eq 'HASH' ? $_[0] : die('Expected hashref instance but got: '.$_[0]);
	tie my %set, 'Tie::IxHash';	# for readability, same order as array
	my $values = $instance->{'ParaValue'};
	for(my $i=0; $i<@$values; $i++) {
		$set{ $instance->{'ParaName'}->[$i] } = $values->[$i];
	}
	return \%set;
}

sub instancesToSets {
	my $instances = ref $_[0] eq 'ARRAY' ? $_[0] : die('Expected arrayref instance but got: '.$_[0]);
	my @result = map { instanceToSet($_) } @$instances;
  return \@result;
}

sub joinArrayHashes {
	my $array1 = ref $_[0] eq 'ARRAY' ? $_[0] : die('Expected arrayref1 instance but got: '.Dumper $_[0]);
	my $array1key = ref $_[1] eq '' ? $_[1] : die('Expected scalar1 but got: '.Dumper $_[1]);
	my $array2 = ref $_[2] eq 'ARRAY' ? $_[2] : die('Expected arrayref2 instance but got: '.Dumper $_[2]);
	my $array2key = ref $_[3] eq '' ? $_[3] : die('Expected scalar2 but got: '.Dumper $_[3]);
	for(my $i=0; $i<@$array1; $i++) {
		for(my $j=0; $j<@$array2; $j++) {
			if ($array1->[$i]->{$array1key} eq $array2->[$j]->{$array2key}) {
				tie my %set, 'Tie::IxHash', %{$array2->[$j]}, %{$array1->[$i]};	# second hash might overwrite keys from first hash, hash from array1 is leading
				$array1->[$i] = \%set;
			}
		}
	}
	return $array1;
}

sub login {
	my ($ua, $host, $username, $password, $force) = @_;
	my $response = $ua->get("http://$host/");
	$response = $ua->get("http://$host/function_module/login_module/login_page/logintoken_lua.lua?_".getUnique()); # _ is just to be unique
	my $token = $response->content =~ />(.*?)</ ? $1 : die('Invalid token result: '.$response->content);
	my $sha256password = sha256_hex($password.$token);
#	print STDERR "token: $token\nsha256: $sha256password\n";
	$response = $ua->post("http://$host/", { 
		'Username' => $username, 
		'Password' => $sha256password, 
		'action' => 'login',
	});	# will always answer with 302, case sensitive
	if ($response->is_redirect) {
		print STDERR "Redirects: ". $response->redirects(). "\n";
		foreach my $r ($response->redirects()) {
			print "Location: " . $r->header('location');
 		}
	}
	my $content = $response->content =~ /(<div id="page_content">.*?)<div id="page_footer">/gs ? $1 : die('No body found: ');
#	print STDERR Dumper $ua->cookie_jar;
	if ($content =~ /var login_err_msg = "(.*?)"/sg) {
		my $error = $1;
		$error =~ s/(\\x([0-9a-f]+))/chr(hex($2))/esg;
		die('Login failed: '.$error); 
	}
	if ($content =~ /"login_warn_span"\s*>(.*?)</sg) {
		my $warning = $1;
		if ($force && $content =~ /name="preempt_sessid" value=['"]?([&#0-9;]+)/sg) {
			my $preempt_sessid = $1;
			$preempt_sessid =~ s/(&#(\d+);)/chr($2)/esg;
			$response = $ua->post("http://$host/",{
				"preempt_sessid" => $preempt_sessid,
				"action" => "preempt",
				"Frm_Logintoken" => "",
			});
		} else {
			die('Quiting because of warning: '.$warning);
		}
	}
	die('Login failed: Reason unknown') if $content =~ /sha256/sg;
	$response = $ua->get("http://$host/");	# act like redirect because the page sets which other pages can be requested
	return $response->content;
}

sub logout {
	my ($ua, $host) = @_;
	return $ua->post("http://$host/", { 'IF_LogOff' => '1', 'IF_LanguageSwitch' => '', 'IF_ModeSwitch' => '' });	# and logout again so somebody can use it without a warning (and also more secure)
}

# returns services and session, you need the last one to change anything
sub getServices {
	my ($ua, $host, $serviceName) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Localnet_LanMgrIpv4_t.lp&Menu3Location=0&_=".getUnique());
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Internet_PortForwarding_t.lp&Menu3Location=0&_=".getUnique());	# returns _sessionTmpToken
	my $sessionToken = $response->content() =~ /_sessionTmpToken = "(.*?)"/s ? $1 : die('No session token found in: '.$response->content());
	$sessionToken =~ s/(\\x([0-9a-f]+))/chr(hex($2))/esg;
	$response = $ua->get("http://$host/common_page/PortForwarding_lua.lua?_=".getUnique());	# to make it complete like it usually does in a browser
	my $servicesXml = $response->content();
	my $hash = XMLin($servicesXml, ForceArray => ['Instance','ParaName','ParaValue']);

	tie my %services, 'Tie::IxHash';	# for readability, same order as array
	my $options = $hash->{'OBJ_PFAPPLIST_ID'}->{'Games'};
	my $values = $options->{'OptionValue'};
	for(my $i=0; $i<@$values; $i++) {
		$services{ lc $values->[$i] } = {
			'_InstID' => $options->{'OptionId'}->[$i],
			'PFAPPList' => $values->[$i],
			'session' => $sessionToken,
		}
	}

	foreach my $instance (@{$hash->{'OBJ_FWPMV4_ID'}->{'Instance'}}) {
		my $set = instanceToSet($instance);
		$set->{'session'} = $sessionToken;
		$services{ lc $set->{'PFAPPList'} } = $set; 
	}

	return \%services;
}

sub getService {
	my ($ua, $host, $serviceName) = @_;
	my $result = getServices(@_);
	return $result->{lc $serviceName};
}

# returns sorted hash with port numbers and matching services
sub getPortsServices {
	my ($ua, $host) = @_;
	my $services = getServices(@_);	# this makes sure the right page is loaded
	my $response = $ua->get("http://$host/common_page/PortForwarding_APPNewandShow_lua.lua?_=".getUnique());	# Get service id, not needed
	tie my %result, 'Tie::IxHash';	# for readability, same order as array
	foreach my $service (values %$services) {
		$response = $ua->get("http://$host/common_page/PortForwarding_APPNewandShow_lua.lua?InterfaceFilter=".$service->{'_InstID'}."&_=".getUnique());	# contains actual port mapping
		my $xml = $response->content;
		my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
		my $set = instanceToSet($hash->{'OBJ_FWAPPLIST_ID'}->{'Instance'}->[0]);
		for( my $port = $set->{'APPSearchMapStartPort'}; $port <= $set->{'APPSearchMapEndPort'}; $port++) {
 			my $serviceList = $result{ $port } || [];
			push @$serviceList, $set;
			$result{ $port } = $serviceList;
		}
	}
	return \%result;
}

sub getPortServices {
	my ($ua, $host, $port) = @_;
	my $ports = getPortsServices($ua, $host);
	return $ports->{$port} || [];
}

sub getPortService {
	my ($ua, $host, $port) = @_;
	my $services = getPortServices($ua, $opt->host, $opt->port);
	my $service = undef;
	if (!@$services) {
		warn("No service defined for port ".$opt->port);
	} elsif (@$services > 1) {
		warn("Specify service via --service instead of port, multiple services found for port ".$opt->port.": ".join(', ', map { '"'.$_->{'APPSearchName'}.'"' } @$services));
	} else {
		$service = $services->[0]->{'APPSearchName'}
	}
	return $service;
}

sub getPortMapping {
	my ($ua, $host, $serviceName) = @_;
	my $service = getService($ua, $host, $serviceName) || die('Service not found: '.$serviceName);	# this makes sure the right page is loaded
	my $response = $ua->get("http://$host/common_page/PortForwarding_APPNewandShow_lua.lua?_=".getUnique());	# Get service id, not needed
	$response = $ua->get("http://$host/common_page/PortForwarding_APPNewandShow_lua.lua?InterfaceFilter=".$service->{'_InstID'}."&_=".getUnique());	# contains actual port mapping
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);

	my $set = instanceToSet($hash->{'OBJ_FWAPPLIST_ID'}->{'Instance'}->[0]);
	return $set;
}

sub addService {
	my ($ua, $host, $serviceName, $ip) = @_;
	my $service = getService($ua, $host, $serviceName) || die('Service not found: '.$serviceName);	# this makes sure the right page is loaded
	# _sessionTmpToken = "\x32\x30\x39\x34\x39\x34\x33\x38\x36\x30\x33\x34\x31\x38\x33\x39";	# changes every time, this one equals 2094943860341839
	$ua->post("http://$host/common_page/PortForwarding_lua.lua", {
		"IF_ACTION" => "Apply",
		"_InstID" => "-1",
		"InternalClient" => $ip,
		"Enable" => "1",
		"Group" => "Games",
		"InputMode" => "0",
		"PFAPPList" => $service->{'PFAPPList'},
		"Btn_cancel_PortForwarding" => "",
		"Btn_apply_PortForwarding" => "",
		"_sessionTOKEN" => $service->{'session'},
	});
	return getService($ua, $host, $serviceName);
}

sub deleteService {
	my ($ua, $host, $serviceName) = @_;
	my $service = getService($ua, $host, $serviceName) || die('Service not found: '.$serviceName);	# this makes sure the right page is loaded
	my $response = $ua->post("http://$host/common_page/PortForwarding_lua.lua", {
		"IF_ACTION" => "Delete",
		"_InstID" => $service->{'_InstID'},
		"InternalClient" => $service->{'InternalClient'},
		"Enable" => "1",
		"Group" => "Games",
		"InputMode" => "0",
		"PFAPPList" => $service->{'PFAPPList'},
		"Btn_cancel_PortForwarding" => "",
		"Btn_apply_PortForwarding" => "",
		"_sessionTOKEN" => $service->{'session'},
	});
	return getService($ua, $host, $serviceName);
}

sub getIp {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Internet_UpLink_Status_t.lp&Menu3Location=0&_=".getUnique());
	$response = $ua->get("http://$host/common_page/Internet_UpLink_Status_lua.lua?_=".getUnique());
	return ($response->content =~ /IPAddress.*?(\d+\.\d+\.\d+\.\d+)/ ? $1 : die('IP not found in response: '.$response->content()));
}

# depricated, replaced by getWlanDevices
sub getWirelessDevices {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=1005&nextpage=home_wlanDevice_listNumLimit_lua.lua&_=".getUnique());
	# http://192.168.1.254/common_page/home_AssociateDevs_lua.lua?AccessMode=WLAN&_=1735909877948
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = instancesToSets($hash->{'OBJ_ACCESSDEV_HOMEWLAN_ID'}->{'Instance'} || []);
	return $devices;
}

# depricated, replaced by getWlanDevices
sub getAssociateWlanDevices {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/common_page/home_AssociateDevs_lua.lua?AccessMode=WLAN&_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = instancesToSets($hash->{'OBJ_ACCESSDEV_ID'}->{'Instance'} || []);
	return $devices;
}

# depricated, replaced by getLanDevices
sub getAssociateLanDevices {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/common_page/home_AssociateDevs_lua.lua?AccessMode=LAN&_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = instancesToSets($hash->{'OBJ_ACCESSDEV_ID'}->{'Instance'} || []);
	return $devices;
}

sub getWlanStatus {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Localnet_Wlan_StatusStatus_t.lp&Menu3Location=0&_=".getUnique());	# get access to status page
	$response = $ua->get("http://$host/common_page/wlanStatus_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $accesspoints = joinArrayHashes(
		instancesToSets($hash->{'OBJ_WLANAP_ID'}->{'Instance'} || []), 'WLANViewName',
		instancesToSets($hash->{'OBJ_WLANSETTING_ID'}->{'Instance'} || []), '_InstID'
	);
	$accesspoints = joinArrayHashes(
		$accesspoints, 'WLANViewName',
		instancesToSets($hash->{'OBJ_WLANCONFIGDRV_ID'}->{'Instance'} || []), 'WLANViewName'
	);
	#	print Dumper $accesspoints;
	return $accesspoints;
}

sub getWlanDevices {
	my ($ua, $host) = @_;
	getWlanStatus($ua, $host);	# get access to status page
	my $response = $ua->get("http://$host/common_page/home_wlanDevice_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = instancesToSets($hash->{'OBJ_ACCESSDEV_ID'}->{'Instance'} || []);
	#	print Dumper $devices;
	return $devices;
}

sub getWlanGuestStatus {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Localnet_wlan_GuestWiFiStatus_t.lp&Menu3Location=0&_=".getUnique());	# get access to status page
	$response = $ua->get("http://$host/common_page/Localnet_wlan_GuestWiFiStatus_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);

	my $accesspoints = joinArrayHashes(
		instancesToSets($hash->{'OBJ_WLANAP_ID'}->{'Instance'} || []), '_InstID',
		instancesToSets($hash->{'OBJ_WLANKEY_ID'}->{'Instance'} || []), '_InstID'
	);
	$accesspoints = joinArrayHashes(
		$accesspoints, '_InstID',
		instancesToSets($hash->{'OBJ_GUESTWIFISTATUS_ID'}->{'Instance'} || []), '_InstID'
	);
	#	print Dumper $accesspoints;
	return $accesspoints;
}

sub getWlanGuestDevices {
	my ($ua, $host) = @_;
	getWlanGuestStatus($ua, $host);
	my $response = $ua->get("http://$host/common_page/Localnet_wlan_GuestWiFiDev_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = instancesToSets($hash->{'OBJ_GUESTWIFIDEV_ID'}->{'Instance'} || []);
	#	print Dumper $hash, $devices;
	return $devices;
}

sub getLanStatus {
	my ($ua, $host) = @_;
	my $response = $ua->get("http://$host/");	# always go back to first page before requesting new pages
	$response = $ua->get("http://$host/getpage.lua?pid=123&nextpage=Localnet_LAN_LocalnetStatus_t.lp&Menu3Location=0&_=".getUnique());	# get access to status page
	$response = $ua->get("http://$host/common_page/lanStatus_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);

	my $accesspoints = joinArrayHashes(
		instancesToSets($hash->{'OBJ_ETH_ID'}->{'Instance'} || []), '_InstID',
		instancesToSets($hash->{'OBJ_WANLAN_ID'}->{'Instance'} || []), '_InstID'
	);
	#	print Dumper $accesspoints;
	return $accesspoints;
}

sub getLanDevices {
	my ($ua, $host) = @_;
	my $accesspoints = getLanStatus($ua, $host);
	my $response = $ua->get("http://$host/common_page/home_lanDevice_lua.lua?_=".getUnique());
	my $xml = $response->content;
	my $hash = XMLin($xml, ForceArray => ['Instance','ParaName','ParaValue']);
	my $devices = joinArrayHashes(
		instancesToSets($hash->{'OBJ_ACCESSDEV_ID'}->{'Instance'} || []), 'Port',
		$accesspoints, 'AliasName'
	);
#	print Dumper $hash, $devices;
	return $devices;

}

