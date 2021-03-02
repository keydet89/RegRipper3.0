#-----------------------------------------------------------
# sfc.pl
# Check SFC settings in the Registry
#
# History
#   20200517 - updated date output format
#   20100305 - updated
#
#
#
# copyright 2020 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sfc;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200517);

sub getConfig{return %config}

sub getShortDescr {
	return "Get SFC values";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching sfc v.".$VERSION);
	::rptMsg("sfc v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				my $name = $v->get_name();
				next unless ($name =~ m/^sfc/i);
				my $str;
				if ($name =~ m/^sfcquota$/i || $name =~ m/^sfcdisable$/i) {
					$str = sprintf "  %-20s  0x%08x",$name,$v->get_data();
				}
				else {
					$str = sprintf "  %-20s  %-20s",$name,$v->get_data();
				}
				::rptMsg($str);
			}
			
		}
		else {
			::rptMsg($key_path." key has no values.");
		}
	}
	else {
		::rptMsg($key_path." key not found.");
		::logMsg($key_path." key not found.");
	}
	::rptMsg("");
# According to http://support.microsoft.com/kb/222193, sfc* values in this key, if 
# it exists, take precedence over and are copied into the values within the Winlogon
# key; see also http://support.microsoft.com/kb/222473/
	my $key_path = "Policies\\Microsoft\\Windows NT\\Windows File Protection";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				my $name = $v->get_name();
				next unless ($name =~ m/^sfc/i);
				my $str;
				if ($name =~ m/^sfcquota$/i || $name =~ m/^sfcdisable$/i) {
					$str = sprintf "  %-20s  0x%08x",$name,$v->get_data();
				}
				else {
					$str = sprintf "  %-20s  %-20s",$name,$v->get_data();
				}
				::rptMsg($str);
			}
			
		}
		else {
			::rptMsg($key_path." key has no values.");
		}
	}
	else {
		::rptMsg($key_path." key not found.");
#		::logMsg($key_path." not found.");
	}
}
1;
