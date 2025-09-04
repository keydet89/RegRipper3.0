#-----------------------------------------------------------
# ares.pl
# 
#
# Change History
#   20250903 (Wladimir Leite)
#            - fix error if any search terms subkey is missing 
#            - extract personal GUID
#            - handle all Search.History subkeys
#            - handle UTF-8 content
#            - minor format adjustments
#   20140730 - updated search terms detection (G. Neives)
#   20130312 - updated based on data provided by J. Weg
#   20120507 - modified to remove the traversing function, to only get
#              a limited amount of data.
#   20110603 - modified F. Kolenbrander
#	       parsing some values according ares source code, like searches and 
#              timestamps.
#   20110530 - created
#   
# References
# 
# copyright 2012 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package ares;
use strict;
use Encode;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20250903);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's Ares Galaxy P2P keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}


my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching Ares v.".$VERSION);
	::rptMsg("ares v.".$VERSION);
        ::rptMsg("- ".getShortDescr()."\n");
        
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Ares';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my %ares = ();
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				$ares{$v->get_name()} = $v->get_data();
			}
			::rptMsg("");
			::rptMsg("RegisterEmail: ".$ares{"RegisterEmail"}) if (exists $ares{"RegisterEmail"});
			::rptMsg("Stats\.LstConnect: ".gmtime($ares{"Stats\.LstConnect"})." UTC") if (exists $ares{"Stats\.LstConnect"});
			::rptMsg("Personal\.Nickname: ".hex2ascii($ares{"Personal\.Nickname"})) if (exists $ares{"Personal\.Nickname"});
			::rptMsg("Personal\.GUID: ".$ares{"Personal\.GUID"}) if (exists $ares{"Personal\.GUID"});
			::rptMsg("General\.Language: ".hex2ascii($ares{"General\.Language"})) if (exists $ares{"General\.Language"});
			::rptMsg("PrivateMessage\.AwayMessage: ".hex2ascii($ares{"PrivateMessage\.AwayMessage"})) if (exists $ares{"PrivateMessage\.AwayMessage"});

		}
		else {
			::rptMsg($key->get_name()." has no values.");
		}
		::rptMsg("");
		getSearchTerms($key);
		
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

sub getSearchTerms {
	my $key = shift;

	::rptMsg("Ares Search Terms:");
	my $count = 0;
	my $search;
	if ($search = $key->get_subkey("Search\.History")) {
		my @subkeys = $search->get_list_of_subkeys();
		foreach my $sk (@subkeys) {
			my @vals = $sk->get_list_of_values();
			if (scalar(@vals) > 0) {
				::rptMsg("    Section: ".$sk->get_name());
				::rptMsg("    LastWrite: ".gmtime($sk->get_timestamp())." (UTC)");
				foreach my $v (@vals) {
					next if ($v->get_name() eq "");
					$count = $count + 1;
					::rptMsg("        ".$count.". ".hex2ascii($v->get_name()));
				}
			}
		}
	}
	::rptMsg("No search terms found\.") if ($count == 0);
}

sub hex2ascii {
	return Encode::decode("utf-8", pack("H*", shift)); 
}

1;
