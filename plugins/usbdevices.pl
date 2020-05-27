#-----------------------------------------------------------
# usbdevices.pl 
# Parses contents of Enum\USB key for USB devices (not only USB storage devices)
# 
# History
#   20200525 - updated date output format
# 	20140416 - updated to include WPD devices (Jasmine Chau)
#   20120522 - updated to report only USBStor devices
#   20100219 - created
#
# copyright 2020 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package usbdevices;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200525);

sub getConfig{return %config}

sub getShortDescr {
	return "Parses Enum\\USB key for USB & WPD devices";	
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
	$reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	::logMsg("Launching usbdevices v.".$VERSION);
	::rptMsg("usbdevices v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
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
	
	my $key_path = $ccs."\\Enum\\USB";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				my @sk = $s->get_list_of_subkeys();
				if (scalar @sk > 0) {
					foreach my $s2 (@sk) {

						my ($desc,$class,$serv,$loc,$mfg,$fname);
						
						eval {
							$desc = $s2->get_value("DeviceDesc")->get_data();
#							::rptMsg($desc." [".$s->get_name()."\\".$s2->get_name()."]");
						};
						
						eval {
							$class = $s2->get_value("Class")->get_data();
						};
						
						eval {
							$serv = $s2->get_value("Service")->get_data();
						};
						
						eval {
							$loc = $s2->get_value("LocationInformation")->get_data();
						};
						
						eval {
							$mfg = $s2->get_value("Mfg")->get_data();
						};
						
						eval {
							$fname = $s2->get_value("FriendlyName")->get_data();
						};
						
						if ($serv eq "USBSTOR") {
							::rptMsg($s->get_name());
							::rptMsg("LastWrite: ".::getDateFromEpoch($s->get_timestamp())."Z");
							::rptMsg("  SN       : ".$s2->get_name());
							::rptMsg("  LastWrite: ".::getDateFromEpoch($s2->get_timestamp())."Z");
#							::rptMsg("DeviceDesc: ".$desc);
#							::rptMsg("Class     : ".$class);
#							::rptMsg("Location  : ".$loc);
#							::rptMsg("MFG       : ".$mfg);
							::rptMsg("");
						}
						elsif (($class eq "WPD") && ($serv eq "WUDFRd")) {
							::rptMsg($s->get_name());
							::rptMsg("LastWrite: ".::getDateFromEpoch($s->get_timestamp())."Z");
							::rptMsg("  SN       : ".$s2->get_name());
							::rptMsg("  LastWrite: ".::getDateFromEpoch($s2->get_timestamp())."Z");
							::rptMsg("MFG       : ".$mfg);
							::rptMsg("FriendlyName: ".$fname);
							::rptMsg("");
						}
					}
				}
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