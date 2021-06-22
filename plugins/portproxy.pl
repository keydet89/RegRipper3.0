#-----------------------------------------------------------
# portproxy.pl
#   Port proxy configuration used by netsh. Used by 
#   attackers for command and control communication.
#
# Change History
#   20210622 - created
#
# References
#   https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
#   https://adepts.of0x.cc/netsh-portproxy-code/
#   https://www.dfirnotes.net/portproxy_detection/
#
# Author: Andreas Hunkeler (@Karneades)
#-----------------------------------------------------------
package portproxy;
use strict;

my %config = (hive          => "System",
              category      => "config",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20210622);

sub getConfig{return %config}

sub getShortDescr {
	return "Get port proxy configuration from PortProxy key";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	my %clsid;
	::logMsg("Launching PortProxy v.".$VERSION);
	::rptMsg("PortProxy v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = "ControlSet001\\Services\\PortProxy\\v4tov4\\tcp";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");

		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				::rptMsg($v->get_name()." - ".$v->get_data());
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;
