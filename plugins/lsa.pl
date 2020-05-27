#-----------------------------------------------------------
# lsa.pl
# 
#
# Change history
#   20200519 - added RunAsPPL value
#   20200517 - updated date output format
#   20140730 - added "EveryoneIncludesAnonymous"
#   20130307 - created
# 
# Reference: 
#   http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html
#   https://www.csoonline.com/article/3393268/how-to-outwit-attackers-using-two-windows-registry-settings.html
#   https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
#
#
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package lsa;

my %config = (hive          => "System",
              hasShortDescr => 1,
              category      => "malware",
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200517);

sub getConfig{return %config}
sub getShortDescr {
	return "Lists specific contents of LSA key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my @pkgs = ("Authentication Packages", "Notification Packages", "Security Packages",
            "EveryoneIncludesAnonymous");

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching lsa v.".$VERSION);
	::rptMsg("lsa v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key();
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my $current;
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		my $ccs = "ControlSet00".$current;
		
		$key_path = $ccs.'\\Control\\LSA';
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite: ".::getDateFromEpoch($key->get_timestamp())."Z");
			::rptMsg("");
			
			eval {
				my $run = $key->get_value("RunAsPPL")->get_data();
				::rptMsg("RunAsPPL value = ".$run);
				::rptMsg("");
				::rptMsg("Per CSOOnline article, setting of \"1\" helps protect against pass-the-hash");
				::rptMsg("and mimikatz-style attacks");
				::rptMsg("");
			};
			
			foreach my $v (@pkgs) {
				eval {
					my $d = $key->get_value($v)->get_data();
					::rptMsg(sprintf "%-25s: ".$d,$v);
				};
			}
			::rptMsg("");
			::rptMsg("Analysis Tips:");
			::rptMsg("- Check Notification Packages value for unusual entries.");
			::rptMsg("- EveryoneIncludesAnonymous = 0 means that Anonymous users do not have the same");
			::rptMsg("  privileges as the Everyone Group.");
		}
		else {
			::rptMsg($key_path." not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;