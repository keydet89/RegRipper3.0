#-----------------------------------------------------------
# svc.pl
# Plugin for Registry Ripper; Access System hive file to get the
# services, display short format (hence "svc", shortened version
# of service.pl plugin); outputs info in .csv format
# 
# Change history
#   20200525 - updated date output format, removed alertMsg() functionality
#   20131010 - added BackDoor.Kopdel checks
#   20130911 - rewrite; fixed issue with running in rip.exe, removed
#              some of the more noisy alerts; added check for FailureActions
#   20130603 - added additional alert functionality
#   20130509 - added alertMsg() functionality, and several alerts
#   20081129 - created
# 
# Ref:
#   http://msdn.microsoft.com/en-us/library/aa394073(VS.85).aspx
#
# Analysis Tip: Several services keys have Parameters subkeys that point to
#   the ServiceDll value; During intrusions, a service key may be added to 
#   the system's Registry; using this module, send the output to .csv format
#   and sort on column B to get the names to line up
#
# Note: some checks/alerts borrowed from E. Schweinsberg's svc_plus.pl 
#       (bethlogic@gmail.com)
#
# copyright 2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package svc;
#use strict;

my %config = (hive          => "System",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200525);

sub getConfig{return %config}
sub getShortDescr {
	return "Lists Services key contents by LastWrite time (CSV)";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %obj = ("nt authority\\localservice" => 1,
           "nt authority\\networkservice" => 1,
           "localsystem" => 1);

my %types = (0x001 => "Kernel driver",
             0x002 => "File system driver",
             0x004 => "Adapter",
             0x010 => "Own_Process",
             0x020 => "Share_Process",
             0x100 => "Interactive",
             0x110 => "Own_Process",
             0x120 => "Share_Process");

my %starts = (0x00 => "Boot Start",
              0x01 => "System Start",
              0x02 => "Auto Start",
              0x03 => "Manual",
              0x04 => "Disabled");

my $display = "";
my $descr   = "";
my $start   = "";
my $image   = "";
my $dll     = "";
my $object  = "";
my $para    = "";

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching svc v.".$VERSION);
	::rptMsg("svc v.".$VERSION); # banner
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my $current;
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		my $ccs = "ControlSet00".$current;
		my $s_path = $ccs."\\Services";
		my $svc;
		my %svcs;
		if ($svc = $root_key->get_subkey($s_path)) {
# Get all subkeys 
			my @subkeys = $svc->get_list_of_subkeys();
			if (scalar (@subkeys) > 0) {
				foreach my $s (@subkeys) {
					$name = $s->get_name();
					
					eval {
						$display = $s->get_value("DisplayName")->get_data();
# take commas out of the display name, replace w/ semi-colons
						$display =~ s/,/;/g;
					};
					$display = "" if ($@);
					
					eval {
						$type = $s->get_value("Type")->get_data();
						(exists $types{$type}) ? ($t = $types{$type}) : ($t = $type);
					};
					if ($@) {
						$type = "";
						$t    = "";
					}
					
					eval {
						$image = $s->get_value("ImagePath")->get_data();
					};
					$image = "" if ($@);
					
					eval {
						$descr = $s->get_value("Description")->get_data();
					};
					
					my $st = "";
					eval {
						$start = $s->get_value("Start")->get_data();
						(exists $starts{$start}) ? ($st = $starts{$start}) : ($st = $start);
					};
					if ($@) {
						$start = "";
						$st    = "";
					}

					eval {
						$object = $s->get_value("ObjectName")->get_data();
					};
					$object = "" if ($@);
					
					my $str = $name."\|".$display."\|".$image."\|".$t."\|".$st."\|".$object."\|".$descr;
					push(@{$svcs{$s->get_timestamp()}},$str) unless ($str eq "");
# Get ServiceDll value, if there is one					
					eval {
						$para = $s->get_subkey("Parameters");
						$dll = $para->get_value("ServiceDll")->get_data();
						my $str = $name."\\Parameters\|\|".$dll."\|\|\|";
						push(@{$svcs{$para->get_timestamp()}},$str);
					};
					
				}
				::rptMsg("Time,Name,DisplayName,ImagePath/ServiceDll,Type,Start,ObjectName");
				foreach my $t (reverse sort {$a <=> $b} keys %svcs) {				
					foreach my $item (@{$svcs{$t}}) {
						my ($n,$d,$i,$t2,$s,$o,$d2) = split(/\|/,$item,7);
#						::rptMsg($t.",".$n.",".$d.",".$i.",".$t2.",".$s.",".$o);
						::rptMsg(::getDateFromEpoch($t)."Z,".$n.",".$d.",".$i.",".$t2.",".$s.",".$o.",".$d2);
					}
				}
			}
			else {
				::rptMsg($s_path." has no subkeys.");
			}			
		}
		else {
			::rptMsg($s_path." not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;