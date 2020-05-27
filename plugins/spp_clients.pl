#-----------------------------------------------------------
# spp_clients
#
# History
#  20130429 - added alertMsg() functionality
#  20120914 - created
#
# copyright 2013 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package spp_clients;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 50, #Vista, Win7
              version       => 20130429);

sub getConfig{return %config}
sub getShortDescr {
	return "Determines volumes monitored by VSS";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching spp_clients v.".$VERSION);
	::rptMsg("spp_clients v.".$VERSION); 
  ::rptMsg("(".getHive().") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("SPP_Clients");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		::rptMsg("Monitored volumes: ");
		my $mon;
		eval {
			$mon = $key->get_value("{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}")->get_data();
			::rptMsg($mon);
		};
		
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;