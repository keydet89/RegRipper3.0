#-----------------------------------------------------------
# printer_settings.pl
#
# History:
#  20200427 - updated output date format
#  20200119 - created
#
# References:
#  
#  https://securelist.com/project-tajmahal/90240/
#    10 Apr 2019
#    Taj Mahal module modifies system to enable data theft, by setting attribute for 
#    printers:
#    Key listed as: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers
#    Value: Attributes
#
#  https://www.undocprint.org/winspool/registry
#    Lists key: SYSTEM\CurrentControlSet\Control\Print\Printers\<printer name>
#    Appear to have the same values available as Software key.
#
#  Testing indicates that the Attributes value in both keys is modified when setting
#  the attribute via the UI.
# 
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package printer_settings;
use strict;

my %config = (hive          => "System, Software",
							hivemask      => 4,
							output        => "report",
							category      => "Configuration",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,  
              version       => 20200427);

sub getConfig{return %config}
sub getShortDescr {
	return "Check printer attributes for KeepPrintedJobs setting";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my %files;
my $str = "";

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching printer_settings v.".$VERSION);
	::rptMsg("printer_settings v.".$VERSION); # banner
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# hive
	my ($current,$ccs);
	my $sel = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($sel)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
		my $key_path = $ccs."\\Control\\Print\\Printers";
		
		if ($key = $root_key->get_subkey($key_path)) {
			my @subkeys = $key->get_list_of_subkeys();
			if (scalar(@subkeys) > 0) {
				foreach my $s (@subkeys) {
					::rptMsg($s->get_name());
					eval {
						my $attr = $s->get_value("Attributes")->get_data();
						if ($attr & 0x100) {
							::rptMsg("  Printer: ".$s->get_name()." KeepPrintedJobs attribute set\.");
							::rptMsg("  Key LastWrite time: ".::getDateFromEpoch($s->get_timestamp())."Z");
						}
					};
				}
			}
		}
	}
	
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers";
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				::rptMsg($s->get_name());
				eval {
					my $attr = $s->get_value("Attributes")->get_data();
					if ($attr & 0x100) {
						::rptMsg("  Printer: ".$s->get_name()." KeepPrintedJobs attribute set\.");
						::rptMsg("  Key LastWrite time: ".::getDateFromEpoch($s->get_timestamp()));
					}
				};
			}
		}
	}
}

1;