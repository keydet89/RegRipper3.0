#-----------------------------------------------------------
# msoffice.pl
# List Office documents for which the user explicitly opted to accept bypassing
#   the default security settings for the application 
#
# Change history
#  20200518 - created 
#
# References
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package  link_click;
use strict;

my %config = (hive          => "NTUSER\.DAT",
							category      => "User Activity",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200518);

sub getConfig{return %config}
sub getShortDescr {
	return "Get UseRWHlinkNavigation value data";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $office_version;
           
sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching  link_click v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	
	::rptMsg("link_click v.".$VERSION);
	::rptMsg("");
# First, let's find out which version of Office is installed
	my @version;
	my $key;
	my $key_path = "Software\\Microsoft\\Office";
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		foreach my $s (@subkeys) {
			my $name = $s->get_name();
			push(@version,$name) if ($name =~ m/^\d/);
		}
	}
# Determine MSOffice version in use	
	my @v = reverse sort {$a<=>$b} @version;
	foreach my $i (@v) {
		eval {
			if (my $o = $key->get_subkey($i."\\User Settings")) {
				$office_version = $i;
			}
		};
	}
	
# Check for UseRWHlinkNavigation value	
# https://support.microsoft.com/en-us/help/4013793/specified-message-identity-is-invalid-error-when-you-open-delivery-rep
	eval {
		if (my $id = $key->get_subkey($office_version."\\Common\\Internet")) {
			my $lw   = $id->get_timestamp();
			my $rw = $id->get_value("UseRWHlinkNavigation")->get_data();
			::rptMsg("Software\\Microsoft\\Office\\".$office_version."\\Common\\Internet");
			::rptMsg("LastWrite time: ".::getDateFromEpoch($lw)."Z");
			::rptMsg("UseRWHlinkNavigation value = ".$rw);
		}
	};	
	
}

1;