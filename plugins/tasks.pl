#-----------------------------------------------------------
# tasks.pl
#   I wrote this plugin to assist with parsing and identifying Scheduled Tasks used by
#   threat actors during engagements; in all of the observed cases, these tasks appear within
#   the root of the TaskCache\Tree key
#
# Change history
#   20200427 - updated output date format
#   20200416 - created
#
# Refs:
#   https://github.com/libyal/winreg-kb/blob/master/documentation/Task%20Scheduler%20Keys.asciidoc
#   http://port139.hatenablog.com/entry/2019/01/12/095429
#
# Copyright (c) 2020 QAR,LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package tasks;
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
sub getShortDescr {return "Checks TaskCache\\Tasks subkeys";}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching tasks v.".$VERSION);
  ::rptMsg("tasks v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr());   
  ::rptMsg("");  
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	my $key_path = 'Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks';
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				
				eval {
					my $path = $s->get_value("Path")->get_data();
					::rptMsg("Path: ".$path);
				};
				
				eval {
					my $uri = $s->get_value("URI")->get_data();
					::rptMsg("URI : ".$uri);
				};
				
				eval {
					my $data = $s->get_value("DynamicInfo")->get_data();
					if (length($data) == 0x1c) {
						my ($t1,$t2) = processDynamicInfo28($data);
# Registration Time associated with TaskScheduler event IDs 106/140
						if ($t1 != 0) {
							::rptMsg("Task Reg Time : ".::getDateFromEpoch($t1)."Z");
						}
# In some cases, the second time stamp seems to be associated with the task
# failing to run for some reason; Last Launch/Last Launch Attempt Time?
						if ($t2 != 0) {
							::rptMsg("Task Last Run : ".::getDateFromEpoch($t2)."Z");
						}				
					}
					elsif (length($data) == 0x24) {
						my ($t1,$t2,$t3) = processDynamicInfo36($data);
						if ($t1 != 0) {
							::rptMsg("Task Reg Time : ".::getDateFromEpoch($t1)."Z");
						}
						if ($t2 != 0) {
							::rptMsg("Task Last Run : ".::getDateFromEpoch($t2)."Z");
						}
						if ($t3 != 0) {
							::rptMsg("Task Completed: ".::getDateFromEpoch($t3)."Z");
						}
					}
					else {
						::rptMsg("DynamicInfo data length = ".length($data)." bytes");
					}
				};
				
#				eval {
#					my $actions = $s->get_value("Actions")->get_data();
#					probe($actions);
#				};
				
				::rptMsg("");
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


#-----------------------------------------------------------
# probe()
#
# Code the uses printData() to insert a 'probe' into a specific
# location and display the data
#
# Input: binary data of arbitrary length
# Output: Nothing, no return value.  Displays data to the console
#-----------------------------------------------------------
sub probe {
	my $data = shift;
	my @d = printData($data);
	::rptMsg("");
	foreach (0..(scalar(@d) - 1)) {
		::rptMsg($d[$_]);
	}
	::rptMsg("");	
}

#-----------------------------------------------------------
# printData()
# subroutine used primarily for debugging; takes an arbitrary
# length of binary data, prints it out in hex editor-style
# format for easy debugging
#
# Usage: see probe()
#-----------------------------------------------------------
sub printData {
	my $data = shift;
	my $len = length($data);
	
	my @display = ();
	
	my $loop = $len/16;
	$loop++ if ($len%16);
	
	foreach my $cnt (0..($loop - 1)) {
# How much is left?
		my $left = $len - ($cnt * 16);
		
		my $n;
		($left < 16) ? ($n = $left) : ($n = 16);

		my $seg = substr($data,$cnt * 16,$n);
		my $lhs = "";
		my $rhs = "";
		foreach my $i ($seg =~ m/./gs) {
# This loop is to process each character at a time.
			$lhs .= sprintf(" %02X",ord($i));
			if ($i =~ m/[ -~]/) {
				$rhs .= $i;
    	}
    	else {
				$rhs .= ".";
     	}
		}
		$display[$cnt] = sprintf("0x%08X  %-50s %s",$cnt,$lhs,$rhs);
	}
	return @display;
}


1;