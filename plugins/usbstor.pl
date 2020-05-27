#-----------------------------------------------------------
# usbstor
#
# History:
#   20200515 - updated date output format
#   20190817 - updated with times from Yogesh's blog
#   20141111 - updated check for key LastWrite times
#		20141015 - added subkey LastWrite times
#   20130630 - added FirstInstallDate, InstallDate query
#   20080418 - created
#
# Ref:
#   http://studioshorts.com/blog/2012/10/windows-8-device-property-ids-device-enumeration-pnpobject/
#   https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10
#   https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html
#   https://www.swiftforensics.com/2013/12/device-lastremovaldate-lastarrivaldate.html
#
# copyright 2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package usbstor;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200515);

sub getConfig{return %config}

sub getShortDescr {
	return "Get USBStor key info";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching usbstor v.".$VERSION);
	::rptMsg("usbstor v.".$VERSION); 
  ::rptMsg("(".getHive().") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($hive);
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

	my $key_path = $ccs."\\Enum\\USBStor";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("USBStor");
		::rptMsg($key_path);
		::rptMsg("");
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				::rptMsg($s->get_name()." [".::getDateFromEpoch($s->get_timestamp())."]");
				
				my @sk = $s->get_list_of_subkeys();
				if (scalar(@sk) > 0) {
					foreach my $k (@sk) {
						my $serial = $k->get_name();
						::rptMsg("  S/N: ".$serial." [".::getDateFromEpoch($k->get_timestamp())."Z]");
# added 20141015; updated 20141111						
						eval {
							::rptMsg("  Device Parameters LastWrite: [".::getDateFromEpoch($k->get_subkey("Device Parameters")->get_timestamp())."Z]");
						};
						eval {
							::rptMsg("  LogConf LastWrite          : [".::getDateFromEpoch($k->get_subkey("LogConf")->get_timestamp())."Z]");
						};
						eval {
							::rptMsg("  Properties LastWrite       : [".::getDateFromEpoch($k->get_subkey("Properties")->get_timestamp())."Z]");
						};
						my $friendly;
						eval {
							$friendly = $k->get_value("FriendlyName")->get_data();
						};
						::rptMsg("    FriendlyName          : ".$friendly) if ($friendly ne "");
						my $parent;
						eval {
							$parent = $k->get_value("ParentIdPrefix")->get_data();
						};
						::rptMsg("    ParentIdPrefix: ".$parent) if ($parent ne "");
# Attempt to retrieve InstallDate/FirstInstallDate from Properties subkeys	
# http://studioshorts.com/blog/2012/10/windows-8-device-property-ids-device-enumeration-pnpobject/		
# https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html			
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
						
					}					
				}
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