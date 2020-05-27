#-----------------------------------------------------------
# wpdbusenum
# Gets contents of Enum\WpdBusEnumRoot keys
# 
#
# History:
#  20200515 - updated date output format
#  20190819 - updated to include time stamps
#  20141111 - updated check for key LastWrite times
#  20141015 - added additional checks
#  20120523 - Added support for a DeviceClasses subkey that includes 
#             "WpdBusEnum" in the names; from MarkW and ColinC
#  20120410 - created
#
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package wpdbusenum;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200515);

sub getConfig{return %config}

sub getShortDescr {
	return "Get WpdBusEnum subkey info";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $reg;

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching wpdbusenum v.".$VERSION);
	::rptMsg("wpdbusenum v.".$VERSION); 
  ::rptMsg("(".getHive().") ".getShortDescr()."\n");
	$reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

# Code for System file, getting CurrentControlSet
	my $current;
	my $ccs;
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
	}
	else {
		::rptMsg($key_path." not found.");
		return;
	}
	
#	my $key_path = $ccs."\\Enum\\WpdBusEnumRoot";
	my $key_path = $ccs."\\Enum\\SWD\\WPDBUSENUM";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {

		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $k (@subkeys) {
				my $dev_class = $k->get_name();
				::rptMsg($dev_class);
				
				eval {
					::rptMsg("  DeviceDesc: ".$k->get_value("DeviceDesc")->get_data());
				};
						
				eval {
					::rptMsg("  Friendly: ".$k->get_value("FriendlyName")->get_data());
				};
						
				eval {
					my $mfg = $k->get_value("Mfg")->get_data();
					::rptMsg("  Mfg: ".$mfg) unless ($mfg eq "");
				};
					
						
				eval {
					::rptMsg("  Properties Key LastWrite: ".::getDateFromEpoch($k->get_subkey("Properties")->get_timestamp())."Z");
				};
						
				my $t;
				eval {
					$t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")->get_value("")->get_data();
					my ($t0,$t1) = unpack("VV",$t);
					::rptMsg("    First InstallDate     : ".::getDateFromEpoch(::getTime($t0,$t1))."Z");
				};
						
				eval {
					$t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065")->get_value("")->get_data();
					my ($t0,$t1) = unpack("VV",$t);
					::rptMsg("    InstallDate           : ".::getDateFromEpoch(::getTime($t0,$t1))."Z");
				};
						
				eval {
						$t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")->get_value("")->get_data();
					my ($t0,$t1) = unpack("VV",$t);
					::rptMsg("    Last Arrival          : ".::getDateFromEpoch(::getTime($t0,$t1))."Z");
				};
						
				eval {
					$t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")->get_value("")->get_data();
					my ($t0,$t1) = unpack("VV",$t);
					::rptMsg("    Last Removal          : ".::getDateFromEpoch(::getTime($t0,$t1))."Z");
				};
						
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	
# Added on 20120523, based on a tweet from Mark Woan while he was attending
# CEIC2012; he attributes this to ColinC.  Googling for this key, I found a
# number of references to USBOblivion, a tool described as being able to wipe
# out (all) indications of USB removable storage devices being connected to
# the system.
	my $key_path = $ccs."\\Control\\DeviceClasses\\{10497b1b-ba51-44e5-8318-a65c837b6661}";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				my $lw   = $s->get_timestamp();
				::rptMsg($name);
				::rptMsg("LastWrite: ".gmtime($lw)." UTC");
				eval {
					my $d = $s->get_value("DeviceInstance")->get_data();
					::rptMsg("  DeviceInstance: ".$d);
				};
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;