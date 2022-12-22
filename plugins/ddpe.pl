#-----------------------------------------------------------
# ddpe
# Get the Machine ID (MCID) and Shield ID (DCID) required to decrypt files using Dell Data Protection Encryption. Also reports the Dell Server URI.
# DDPE policies vary by organization, which may include encryption of registry hive files. Will not work if policy enforces encryption of the SOFTWARE registry hive.
#
# History:
# 20221128 - created
# 20221221 - fixed typos
#
# Ref: 
# https://dl.dell.com/topicspdf/dell-data-protection-encryption_administrator-guide19_en-us.pdf
# https://www.magnetforensics.com/blog/working-with-dell-data-protection-encryption-ddpe-in-axiom-cyber/
#
# Author: Derek Eiri, derekceiri@gmail.com
#-----------------------------------------------------------
package ddpe;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20221128);

sub getConfig{return %config}

sub getShortDescr {
	return "Get the Machine ID (MCID) and Shield ID (DCID) needed to decrypt files using Dell Encryption. Also reports the Dell Server URI.";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching ddpe v.".$VERSION); # banner
	::rptMsg("ddpe v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	
	my @paths = ("Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CMGShield",
				"Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CMGShield\\Servlet");
	
	foreach my $key_path (@paths) {
	if ($key = $root_key->get_subkey($key_path)) {
		
		eval {
			my $mcid = $key->get_value("MCID")->get_data();
			::rptMsg("MachineID    = ".$mcid);
		};
		
		eval {
			my $dcid = $key->get_value("DCID")->get_data();
			::rptMsg("ShieldID = ".$dcid);
		};
		eval {
			my $uri = $key->get_value("")->get_data();
			::rptMsg("".$uri);
		}
	}
	else {
			::rptMsg($key_path." not found.");
	}
	}
}

1;
