#-----------------------------------------------------------
# netsh.pl
#
# Change history:
#  20200515 - updated date output format
#  20190316 - created
# 
# Ref:
#  https://attack.mitre.org/techniques/T1128/
#  https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html
#
# copyright 2020 QAR,LLC 
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package netsh;
use strict;

my %config = (hive          => "Software",
							category      => "autostart",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       =>  20200515);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets list of NetSH helper DLLs";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching netsh v.".$VERSION);
	::rptMsg("netsh v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $key_path = 'Microsoft\\Netsh';
	
	::rptMsg("NetSH");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		my @vals = $key->get_list_of_values();
		if (scalar @vals > 0) {
			::rptMsg("");
			::rptMsg(sprintf "%-15s %-25s","Name","DLL Name");
			foreach my $v (@vals) {
				::rptMsg(sprintf "%-15s %-25s",$v->get_name(),$v->get_data());
			}
		}
		else {
			
		}
	}
	else {
		
	}
}
1;
