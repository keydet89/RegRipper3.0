#-------------------------------------------------------------------------
# sevenzip.pl
# 
# Change history
#   20210329 - added LastWrite times for parent keys and printed header
#   20200515 - minor updates
#   20130315 - minor updates added
#   20100218 - created
#
# References
#
# 
#
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#
# revisions 2021-03-29 by Dan O'Day, d@4n68r.com
#-------------------------------------------------------------------------
package sevenzip;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20210329);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets records of histories from 7-Zip keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	my %hist;
	::logMsg("Launching 7-zip v.".$VERSION);
	::rptMsg("sevenzip v.".$VERSION); # banner
    ::rptMsg("- ".getShortDescr()."\n"); # banner
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my @keys = ('Software\\7-Zip',
	            'Software\\Wow6432Node\\7-Zip');

	foreach my $key_path (@keys) {
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
		
			eval {
				my $s = $key->get_subkey("FM");
				::rptMsg("FM LastWrite: [".::getDateFromEpoch($s->get_timestamp())."Z]");
				::rptMsg("");
			};
			
			eval {
				my $s = $key->get_subkey("Compression");
				::rptMsg("Compression LastWrite: [".::getDateFromEpoch($s->get_timestamp())."Z]");
				::rptMsg("");
			};
			
			eval {
				my $s = $key->get_subkey("Extraction");
				::rptMsg("Extraction LastWrite: [".::getDateFromEpoch($s->get_timestamp())."Z]");
				::rptMsg("");
			};
			
			eval {
				::rptMsg("FM\\PanelPath0: ".$key->get_subkey("FM")->get_value("PanelPath0")->get_data());
				::rptMsg("");
			};

			eval {
				::rptMsg("Compression\\ArcHistory:");
				my $copy = $key->get_subkey("Compression")->get_value("ArcHistory")->get_data();
				my @c = split(/\00\00/,$copy);
				foreach my $hist (@c) {
					$hist =~ s/\00//g;
					::rptMsg("  ".$hist);
				}
			};
		
			eval {
				::rptMsg("Extraction\\PathHistory:");
				my $copy = $key->get_subkey("Extraction")->get_value("PathHistory")->get_data();
				my @c = split(/\00\00/,$copy);
				foreach my $hist (@c) {
					$hist =~ s/\00//g;
					::rptMsg("  ".$hist);
				}
				::rptMsg("");
			};
			
			eval {
				::rptMsg("FM\\CopyHistory:");
				my $copy = $key->get_subkey("FM")->get_value("CopyHistory")->get_data();
				my @c = split(/\00\00/,$copy);
				foreach my $hist (@c) {
					$hist =~ s/\00//g;
					::rptMsg("  ".$hist);
				}
				::rptMsg("");
			};
			
			eval {
				::rptMsg("FM\\FolderHistory:");
				my $copy = $key->get_subkey("FM")->get_value("FolderHistory")->get_data();
				my @c = split(/\00\00/,$copy);
				foreach my $hist (@c) {
					$hist =~ s/\00//g;
					::rptMsg("  ".$hist);
				}
			};

		}
		else {
			::rptMsg($key_path." not found.");
		}
	}
}
1;
