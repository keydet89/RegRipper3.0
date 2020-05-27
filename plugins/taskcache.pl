#-----------------------------------------------------------
# taskcache.pl
#   I wrote this plugin to assist with parsing and identifying Scheduled Tasks used by
#   threat actors during engagements; in all of the observed cases, these tasks appear within
#   the root of the TaskCache\Tree key.
#
#   NOTE: This plugin only checks keys in the root of the TaskCache\Tree key, it does not 
#         traverse subkeys for additional info
#
# Change history
#   20200427 - updated output date format
#   20200416 - created
#
# Refs:
#   https://github.com/libyal/winreg-kb/blob/master/documentation/Task%20Scheduler%20Keys.asciidoc
#   http://port139.hatenablog.com/entry/2019/01/12/095429
#   
#
# Copyright (c) 2020 QAR,LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package taskcache;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "program execution",
              version       => 20200427);

my $VERSION = getVersion();

sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {return "Checks TaskCache\\Tree root keys (not subkeys)";}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching taskcache v.".$VERSION);
  ::rptMsg("taskcache v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr());   
  ::rptMsg("");  
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	my $key_path = 'Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache';
	if ($key = $root_key->get_subkey($key_path)) {
# First, get subkeys
		if (my $tree = $key->get_subkey("Tree")) {
			my @subkeys = $tree->get_list_of_subkeys();
			if (scalar @subkeys > 0) {
				foreach my $s (@subkeys) {
					if (my $id = $s->get_value("Id")) {
						::rptMsg($s->get_name());
						::rptMsg("LastWrite: ".::getDateFromEpoch($s->get_timestamp())."Z");
						my $g = $id->get_data();
						$g =~ s/\00$//;
						::rptMsg("Id: ".$g);
						
						if (my $tasks = $key->get_subkey("Tasks")) {
							if (my $guid = $tasks->get_subkey($g)) {
								if (my $dyn = $guid->get_value("DynamicInfo")) {
									my $data = $dyn->get_data();
									if (length($data) == 0x1c) {
										my ($t1,$t2) = processDynamicInfo28($data);
# Registration Time associated with TaskScheduler event IDs 106/140
										if ($t1 != 0) {
											::rptMsg("Task Reg Time: ".::getDateFromEpoch($t1)."Z");
										}
# In some cases, the second time stamp seems to be associated with the task
# failing to run for some reason; Last Launch/Last Launch Attempt Time?
										if ($t2 != 0) {
											::rptMsg("Task Last Run: ".::getDateFromEpoch($t2)."Z");
										}
										
									}
									elsif (length($data) == 0x24) {
										my ($t1,$t2,$t3) = processDynamicInfo36($data);
										if ($t1 != 0) {
											::rptMsg("Task Reg Time: ".::getDateFromEpoch($t1)."Z");
										}
										if ($t2 != 0) {
											::rptMsg("Task Last Run: ".::getDateFromEpoch($t2)."Z");
										}
										if ($t3 != 0) {
											::rptMsg("Task Completed: ".::getDateFromEpoch($t3)."Z");
										}

									}
									else {
										::rptMsg("DynamicInfo data length = ".length($data)." bytes");
									}
									
								}
							}
							else {
#								::rptMsg($key_path."\\Tasks\\".$g." not found.");
							}
						}
						::rptMsg("");
					};
				}
			}
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

sub processDynamicInfo28 {
#win7
	my $data = shift;
	my ($t0,$t1) = unpack("VV",substr($data,4,8));
	my ($d0,$d1) = unpack("VV",substr($data,12,8));
	return(::getTime($t0,$t1),::getTime($d0,$d1));
}

sub processDynamicInfo36 {
#win10	
	my $data = shift;
	my ($t0,$t1) = unpack("VV",substr($data,4,8));
	my ($d0,$d1) = unpack("VV",substr($data,12,8));
	my ($r0,$r1) = unpack("VV",substr($data,0x1c,8));
	return(::getTime($t0,$t1),::getTime($d0,$d1),::getTime($r0,$r1));
}
1;
