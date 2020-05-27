#-----------------------------------------------------------
# environment.pl
#   Extracts environment variables from NTUSER.DAT and System hives
# 
# Change history
#   20200512 - created
#
# References
#  http://www.hexacorn.com/blog/2014/11/14/beyond-good-ol-run-key-part-18/
#  UserInitMprLogonScript value  - https://eqllib.readthedocs.io/en/latest/analytics/54fff7e8-f81d-4169-b820-4cbff0133e2d.html
#  Cor_profiler values           - https://redcanary.com/blog/cor_profiler-for-persistence/
#  Seen used by Blue Mockingbird - https://redcanary.com/blog/blue-mockingbird-cryptominer/
#
# Copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package environment;
use strict;

my %config = (hive          => "System, NTUSER\.DAT",
              hasShortDescr => 1,
              category      => "autostart",
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200512);

my $VERSION = getVersion();

sub getDescr {}
sub getRefs {}
sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getShortDescr {
	return "Get environment vars from NTUSER\.DAT & System hives";
}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching environment v.".$VERSION);
  ::rptMsg("environment v.".$VERSION); 
  ::rptMsg("(".getHive().") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my %guess = ();
	my $hive_guess = "";
	my %guess = ::guessHive($hive);
	foreach my $g (keys %guess) {
		$hive_guess = $g if ($guess{$g} == 1);
	}
	
	my $key = ();
	my $key_path = ();
	
	my @val_names = ("UserInitMprLogonScript","cor_enable_profiling","cor_profiler","cor_profiler_path");
	
	if ($hive_guess eq "system") {
		my $ccs = ();
		if ($key = $root_key->get_subkey('Select')) {
			$ccs = "ControlSet00".$key->get_value("Current")->get_data();
		}
		$key_path = $ccs."\\Control\\Session Manager\\Environment";
	}
	elsif ($hive_guess eq "ntuser") {
		$key_path = "Environment";
		
		
	}
	else {
		$key_path = "Environment";
	}
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time: ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {

			foreach my $v (@vals) {
				my $name = $v->get_name();
				::rptMsg(sprintf "%-25s %-50s",$name,$v->get_data());
				
				foreach my $n (@val_names) {
					if ($name eq $n) {
						::rptMsg("**ALERT: ".$n." value found: ".$v->get_data());
					}
				}
			}
		} 
		else {
			::rptMsg($key_path." has no values.");
		}
	} else {
		::rptMsg($key_path." not found.");
	}
#	::rptMsg("");
}

1;
