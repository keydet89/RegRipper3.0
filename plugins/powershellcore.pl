#-----------------------------------------------------------
# powershellcore.pl
#   
#
# Change history
#   20200525 - updated date output format
#   20181005 - created
#
# References
#   http://files.brucon.org/2018/03-Matt-Ryan-ReInvestigating-Powershell-Attacks.pdf
#
# Copyright (c) 2020 QAR, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package powershellcore;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "config",
              version       => 20200525);
my $VERSION = getVersion();

sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {
	return "Extracts PowerShellCore settings";
}
sub getRefs {}

sub pluginmain {

	# Declarations #
	my $class = shift;
	my $hive = shift;

	# Initialize #
	::logMsg("Launching powershellcore v.".$VERSION);
  ::rptMsg("powershellcore v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");     
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	
	my @paths = ("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
	             "Wow6432Node\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
	             "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
	             "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers");
	
	foreach my $key_path (@paths) {
	# If AppCompatFlags path exists #
		if ($key = $root_key->get_subkey($key_path)) {

		# Return # plugin name, registry key and last modified date #
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
			::rptMsg("");

		# Extract # all keys from AppCompatFlags registry path #
			my @vals = $key->get_list_of_values();

		# If # registry keys exist in path #
			if (scalar(@vals) > 0) {

			# Extract # all key names+values for AppCompatFlags registry path #
				foreach my $v (@vals) {
					::rptMsg($v->get_name()." -> ".$v->get_data());
				}

		# Error # key value is null #
			} else {
				::rptMsg($key_path." found, has no values.");
			}
		}
		else {
# We're checking several keys in each hive, so if $key_path isn't found,
# don't generate a report 			
#			::rptMsg($key_path." not found.");
		}
	} 
	# Return # obligatory new-line #
	::rptMsg("");
	
# Get all programs for which PCA "came up", for a user, even if no compatibility modes were
# selected	
# Added 20130706 by H. Carvey
	@paths = ("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted",
	          "Wow6432Node\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted",
	          "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted",
	          "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted");
	   
	foreach my $key_path (@paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			my @vals = $key->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					::rptMsg("  ".$v->get_name());
				}
			}
			else {
				::rptMsg($key_path." found, has no values\.");
			}
		}
		else {
# As above, don't report on key paths not found			
#			::rptMsg($key_path." not found\.");
		}
	}
	
# Get Store key contents
# selected	
# Added 20130930 by H. Carvey
	@paths = ("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
	          "Wow6432Node\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
	          "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
	          "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");
	   
	foreach my $key_path (@paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			my @vals = $key->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					
					my ($t0,$t1) = unpack("VV",substr($v->get_data(),0x2C,8));
					my $t = ::getTime($t0,$t1);
					
					::rptMsg("  ".::getDateFromEpoch($t)."Z - ".$v->get_name());
				}
			}
			else {
				::rptMsg($key_path." found, has no values\.");
			}
		}
		else {
# As above, don't report on key paths not found			
#			::rptMsg($key_path." not found\.");
		}
	}	
	
# Added check for use of AppCompat DB for persistence
# 21051021, H. Carvey	
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom";
	if ($key = $root_key->get_subkey($key_path)){
		my @subkeys = $key->get_list_of_subkeys($key);
		if (scalar @subkeys > 0) {
			foreach my $sk (@subkeys) {
				::rptMsg("Key name: ".$sk->get_name());
				::rptMsg("LastWrite time: ".::getDateFromEpoch($sk->get_timestamp())."Z");
				
				my @vals = $sk->get_list_of_values();
				if (scalar @vals > 0) {
					foreach my $v (@vals) {
						my $name = $v->get_name();
						my ($t0,$t1) = unpack("VV",$v->get_data());
						my $l = ::getTime($t0,$t1);
						my $ts   = ::getDateFromEpoch($l);
						::rptMsg("  ".$name."  ".$ts."Z");
					}
				}
				::rptMsg("");
			}
		}
	}
	
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB";
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys($key);
		if (scalar @subkeys > 0) {
			foreach my $sk (@subkeys) {
				my($path, $descr, $ts);
				eval {
					$descr = $sk->get_value("DatabaseDescription")->get_data();
					::rptMsg("Description: ".$descr);
				};
				
				eval {
					$path = $sk->get_value("DatabasePath")->get_data();
					::rptMsg("  Path: ".$path);
				};
				
				eval {
					my ($t0,$t1) = unpack("VV",$sk->get_value("DatabaseInstallTimeStamp")->get_data());
					my $l = ::getTime($t0,$t1);
					$ts = ::getDateFromEpoch($l);
					::rptMsg("  Install TimeStamp: ".$ts."Z");
				};
				
				::rptMsg("");
				
			}
		}
	}
}

1;
