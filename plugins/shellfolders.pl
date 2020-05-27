#-----------------------------------------------------------
# shellfolders.pl
# A threat actor can maintain persistence by modifying the StartUp folder location,
# and using that new location for persistence 
#
# Change history
#  20200515 - updated date output format
#  20190902 - removed alert() function
#  20131028 - updated to include User Shell Folders entry
#  20131025 - created
#
# References
#   http://www.fireeye.com/blog/technical/malware-research/2013/10/evasive-tactics-terminator-rat.html
#   http://www.symantec.com/connect/articles/most-common-registry-key-check-while-dealing-virus-issue
# 
# copyright 2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package shellfolders;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200515);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's shell folders values";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching shellfolders v.".$VERSION);
	::rptMsg("shellfolders v.".$VERSION); 
    ::rptMsg(getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		
		eval {
			my $start = $key->get_value("Startup")->get_data();
			::rptMsg("StartUp folder : ".$start);
		};
	}
	else {
		::rptMsg($key_path." not found.");
	}
	
# added 20131028	
	::rptMsg("");
	$key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders';
	if ($key = $root_key->get_subkey($key_path)) {
	::rptMsg($key_path);
	::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		
		eval {
			my $start = $key->get_value("Startup")->get_data();
			::rptMsg("StartUp folder : ".$start);
		};
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;