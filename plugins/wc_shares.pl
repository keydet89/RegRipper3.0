#-----------------------------------------------------------
# wc_shares.pl
# 
#
# Change history
#   20200515 - updated date output format
#   20171016 - created
#
# References
#
# 
# copyright 2020 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package wc_shares;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200515);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's WorkgroupCrawler/Shares subkeys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching wc_shares v.".$VERSION);
	::rptMsg("wc_shares v.".$VERSION); # banner
    ::rptMsg("- ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WorkgroupCrawler\\Shares';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) { 
				::rptMsg($s->get_name()." [".::getDateFromEpoch($s->get_timestamp())."Z]");
				
				eval {
					my $filename = $s->get_value("Filename")->get_data();
					::rptMsg("  Filename        = ".$filename);
					
				};
				
				eval {
					my ($t0,$t1) = unpack("VV",$s->get_value("DateLastVisited")->get_data());
					my $last = ::getTime($t0,$t1);
					::rptMsg("  DateLastVisited = ".::getDateFromEpoch($last)."Z");
					
				};
				::rptMsg("");	
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;