#-----------------------------------------------------------
# ica_sessions.pl
#   Collects Citrix ICA Session information
#
# Change history
#   20200528 - created
#
# References
#   
#
# Copyright 2020 Quantum Analytics Research, LLC
# FOR USE BY ARETE ONLY
#-----------------------------------------------------------
package ica_sessions;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "program execution",
              version       => 20200528);
my $VERSION = getVersion();

# Functions #
sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {
	return "ARETE ONLY - Extracts Citrix ICA Session info";
}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching ica_sessions v.".$VERSION);
  ::rptMsg("ica_sessions v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");    
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	my $key_path = "Citrix\\Ica\\Session";
	
	my %vals = (1 => "ClientName",
	            2 => "ClientAddress",
	            3 => "DomainName",
	            4 => "PublishedName",
	            5 => "UserName");
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				if (my $conn = $s->get_subkey("Connection")) {
					::rptMsg(sprintf "%-32s : %-15s","Session",$s->get_name());
					::rptMsg(sprintf "%-32s : %-15s","Connection subkey LastWrite time",::getDateFromEpoch($conn->get_timestamp())."Z");
					foreach my $v (sort keys %vals) {
						eval {
							my $i = $conn->get_value($vals{$v})->get_data();
							::rptMsg(sprintf "%-32s : %-15s",$vals{$v},$i);
						};
					}
				}
				::rptMsg("");
			}
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;
