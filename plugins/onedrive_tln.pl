#-----------------------------------------------------------
# onedrive_tln.pl
# 
#
# Change history
#	  20190823 - created
#
# References
#   
# 
# copyright 2019 Quantum Analytics Research, LLC
#-----------------------------------------------------------
package onedrive_tln;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20190823);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's OneDrive key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
#	::logMsg("Launching onedrivev.".$VERSION);
#	::rptMsg("onedrive v.".$VERSION); 
#  ::rptMsg("(".getHive().") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = "Software\\Microsoft\\OneDrive";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
#		::rptMsg($key_path);
		
		my $user = ();
		eval {
			$user = $key->get_subkey("Accounts\\Personal")->get_value("UserCID")->get_data();
		};
		
		eval {
			my $t = $key->get_subkey("Accounts\\Personal")->get_value("ClientFirstSignInTimestamp")->get_data();
			my $s = unpack("Vx4",$t);
			::rptMsg($s."|REG|||".$user." OneDrive - ClientFirstSignInTimestamp");
		};
		
		eval {
			my $t = $key->get_subkey("Accounts\\Personal")->get_value("NextOneRmUpdateTime")->get_data();
			my $s = unpack("Vx4",$t);
			::rptMsg($s."|REG|||".$user." OneDrive - NextOneRmUpdateTime");
		};
		
		eval {
			my $t = $key->get_subkey("Accounts\\Personal")->get_value("NextMigrationScan")->get_data();
			my $s = unpack("Vx4",$t);
			::rptMsg($s."|REG|||".$user." OneDrive - NextMigrationScan");
		};
	}
	else {
#		::rptMsg($key_path." not found.");
	}
}

1;