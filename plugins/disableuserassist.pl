#-----------------------------------------------------------
# disableuserassist.pl
#  Start_TrackEnabled and Start_TrackProgs values set 0, denotes that UserAssist was disabled on the host.
# 
# Change History:
#   20230710 - created
#
# Ref: 
#  https://github.com/carlospolop/hacktricks/blob/master/forensics/basic-forensic-methodology/anti-forensic-techniques.md
#  https://learn.microsoft.com/en-gb/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
#
# Author: Ajith Ravindran, ravindran.ajith@hotmail.com
#-----------------------------------------------------------
package disableuserassist;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20230710);

sub getConfig{return %config}

sub getShortDescr {
	return "Get Start_TrackEnabled and Start_TrackProgs values which confirm if UserAssist was disabled.";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching disableuserassist v.".$VERSION);
	::rptMsg("disableuserassist v.".$VERSION); 
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	my $key;
	my $key_path;


	foreach my $i ("","Software\\") {
		$key_path = $i.'Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced';
		if ($key = $root_key->get_subkey($key_path)) {
			eval {
				my $Start_TrackProgs = $key->get_value("Start_TrackProgs")->get_data();
				my $Start_TrackEnabled = $key->get_value("Start_TrackEnabled")->get_data();
				::rptMsg($key_path." Start_TrackProgs value = ".$Start_TrackProgs);
				::rptMsg($key_path." Start_TrackEnabled value = ".$Start_TrackEnabled);
				::rptMsg("Value 0 indicate UserAssist is disabled");
				::rptMsg("Key LastWrite time: ".::getDateFromEpoch($key->get_timestamp())."Z");
			};			
		}
	}

}

1;
