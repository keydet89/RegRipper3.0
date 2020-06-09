#-----------------------------------------------------------
# printdemon.pl
#
# History
#   20200514 - created
#
# Refs:
#		https://windows-internals.com/printdemon-cve-2020-1048/
#   https://twitter.com/aionescu/status/1260466215299973121
#
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package printdemon;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              category      => "persistence",
              hasDescr      => 0,
              hasRefs       => 1,
              osmask        => 22,
              version       => 20200514);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets value assoc with printer ports and descriptions";	
}
sub getDescr{}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching printdemon v.".$VERSION);
	::rptMsg("printdemon v.".$VERSION); # banner
  ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\Windows NT\CurrentVersion';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {

# First, get the Ports values
		if (my $ports = $key->get_subkey("Ports")) {
			::rptMsg("Ports key");
			::rptMsg("LastWrite time: ".::getDateFromEpoch($ports->get_timestamp())."Z");
			::rptMsg("");
			my @vals = $ports->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					::rptMsg(sprintf "%-15s %-50s",$v->get_name(),$v->get_data());

				}
			}
		}
		else {
			::rptMsg("Ports key not found.");
		}		
		::rptMsg("");
		::rptMsg("Print\\Printers keys, Port values");
# Now, get the Port value for each printer
		if (my $pr = $key->get_subkey('Print\Printers')) {
			my @printers = $pr->get_list_of_subkeys();
			if (scalar(@printers) > 0) {
				foreach my $p (@printers) {
					::rptMsg("Printer       : ".$p->get_name());
					::rptMsg("LastWrite time: ".::getDateFromEpoch($p->get_timestamp())."Z");
					my $pp = ();
					eval {
						$pp = $p->get_value("Port")->get_data();
						::rptMsg("Port          : ".$pp);
					};
					::rptMsg("");
				}
			}
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;