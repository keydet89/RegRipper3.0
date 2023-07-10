#-----------------------------------------------------------
# disableeventlog
#	Plugin identifies if Windows Event Logging was disabled or modified by making changes to Windows Registry.
#	Registry Key value of 4 for the subkey HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\start, denotes the EventLog service is disabled.
#	Subkey HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security\File contains the location where Security.evtx files are stored.
#	If the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNt is present, Windows will assume the operating system to be WinPE and would not log event logs.
#
# Change History:
#   20230710 - created
#
# Ref:
#	https://twitter.com/0gtweet/status/1182516740955226112
#	https://ptylu.github.io/content/report/report.html?report=25
#
# Author: Ajith Ravindran, ravindran.ajith@hotmail.com
#-----------------------------------------------------------
package disableeventlog;
use strict;

my %config = (hive          => "System",
              hasShortDescr => 1,
              category      => "config",
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20230710);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets EventLog -> Start value from System hive; Checks if default Security.evtx path is modified; Checks if MiniNt registry key is set.";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching disableeventlog v.".$VERSION);
	::rptMsg("disableeventlog v.".$VERSION); # banner
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my ($current,$ccs);
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
		my $el_path = $ccs."\\Services\\EventLog";
		
		my $el;
		if ($el = $root_key->get_subkey($el_path)) {
			eval {
				my $start = $el->get_value("Start")->get_data();
				if ($start == 4) {
					::rptMsg("Start = 4; Event Log service disabled");
				}
				::rptMsg("Start    = ".$start.". EventLog service is not disabled.");				
			};
			::rptMsg("Start value not found.") if ($@);
			}
		else {
			::rptMsg($el_path." not found.");
		}
		
		my $els_path = $ccs."\\Services\\EventLog\\Security";
		
		my $els;
		if ($els = $root_key->get_subkey($els_path)){
		eval {
				my $file_value = $els->get_value("File")->get_data();
					
				if ($file_value != "%SystemRoot%\System32\winevt\Logs\Security.evtx") {
					::rptMsg("Default path for storing Security.evtx is modified to ".$file_value);
				}
				::rptMsg("Security.evtx files are stored to ".$file_value);				
			};
			::rptMsg("File value not found.") if ($@);	

		}
		else {
			::rptMsg($els_path." not found.");
		}
		
		
		my $PE_path = $ccs."\\Control\\MiniNt";
		my $pe;
		if ($pe = $root_key->get_subkey($PE_path)){
			::rptMsg($pe." path exists. Windows would not log events to respective event log files.");
		}
		::rptMsg($PE_path." is not set.");				
		
	}
	else {
		::rptMsg($key_path." not found.");
	}
	
}

1;