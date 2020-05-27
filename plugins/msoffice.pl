#-----------------------------------------------------------
# msoffice.pl
# List Office documents for which the user explicitly opted to accept bypassing
#   the default security settings for the application 
#
# Change history
#  20200518 - updated date output format, minor updates
#  20200316 - minor update
#  20200102 - added check for UseRWHLinkNavigation value
#  20190902 - added check for OLE PackagerPrompt & AdditionalActionsDLL values
#  20190822 - created 
#
# References
# 20190626 updates
#  https://decentsecurity.com/block-office-macros
#  https://gist.github.com/PSJoshi/749cf1733217d8791cf956574a3583a2
#
#  http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
#  ForensicArtifacts.com posting by Andrew Case:
#    http://forensicartifacts.com/2012/07/ntuser-trust-records/
#  http://archive.hack.lu/2010/Filiol-Office-Documents-New-Weapons-of-Cyberwarfare-slides.pdf
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package  msoffice;
use strict;

my %config = (hive          => "NTUSER\.DAT",
							category      => "User Activity",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200518);

sub getConfig{return %config}
sub getShortDescr {
	return "Get user's MSOffice content";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $office_version;
my %vba = (1 => "Enable all macros",
           2 => "Disable all macros w/ notification",
           3 => "Disalbe all macros except dig. signed macros",
           4 => "Disalbe all macros w/o notification");
           
sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching  msoffice v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	
	::rptMsg("msoffice v.".$VERSION);
	::rptMsg("");
# First, let's find out which version of Office is installed
	my @version;
	my $key;
	my $key_path = "Software\\Microsoft\\Office";
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		foreach my $s (@subkeys) {
			my $name = $s->get_name();
			push(@version,$name) if ($name =~ m/^\d/);
		}
	}
# Determine MSOffice version in use	
	my @v = reverse sort {$a<=>$b} @version;
	foreach my $i (@v) {
		eval {
			if (my $o = $key->get_subkey($i."\\User Settings")) {
				$office_version = $i;
			}
		};
	}
	
# Check Identities
	eval {
		if (my $id = $key->get_subkey($office_version."\\Common\\Identity\\Identities")) {
			my @subkeys = $id->get_list_of_subkeys();
			if (scalar @subkeys > 0) {
				::rptMsg("Office Identities");
				foreach my $s (@subkeys) {
					my $name = $s->get_value("FriendlyName")->get_data();
					my $email = $s->get_value("EmailAddress")->get_data();
					::rptMsg($name." (".$email.")") if ($name ne "");
				}
			}
		}
		::rptMsg("");
	};	
	
# Added 20190902
# check for AdditionalActionsDlls	
	eval {
		if (my $id = $key->get_subkey($office_version."\\Common")) {
			my $aa = $id->get_value("AdditionalActionsDLL")->get_data();
			::rptMsg("AdditionalActionsDLL value = ".$aa);
			::rptMsg("");
		}
	};	
	
# added 20200102
# Check for UseRWHlinkNavigation value	
# https://support.microsoft.com/en-us/help/4013793/specified-message-identity-is-invalid-error-when-you-open-delivery-rep
	eval {
		if (my $id = $key->get_subkey($office_version."\\Common\\Internet")) {
			my $lw   = $id->get_timestamp();
			my $rw = $id->get_value("UseRWHlinkNavigation")->get_data();
			::rptMsg("Software\\Microsoft\\Office\\".$office_version."\\Common\\Internet");
			::rptMsg("LastWrite time: ".::getDateFromEpoch($lw)."Z");
			::rptMsg("UseRWHlinkNavigation value = ".$rw);
			::rptMsg("");
		}
	};	
	
# Now that we have the most recent version of Office installed, let's 
# start looking at the various subkeys
	my @apps = ("Word","PowerPoint","Excel","Access");	
	
	foreach my $app (@apps) {
# Check for DontUpdateLinks value
		eval {
			if (my $opt = $key->get_subkey($office_version."\\".$app."\\Options")) {
				my $upd = $opt->get_value("DontUpdateLinks")->get_data();
				::rptMsg("DontUpdateLinks value: ".$upd);
				::rptMsg("");
			}
		};		
# Check values under "Security" key
		eval {
			if (my $sec = $key->get_subkey($office_version."\\".$app."\\Security")) {
				my $vb = $sec->get_value("VBAWarnings")->get_data();
				::rptMsg("VBAWarnings value: ".$vba{$vb});
				::rptMsg("");
			}
		};
		
		eval {
			if (my $sec = $key->get_subkey($office_version."\\".$app."\\Security")) {
				my $b = $sec->get_value("blockcontentexecutionfrominternet")->get_data();
				::rptMsg("blockcontentexecutionfrominternet value: ".$b);
			}
		};

# Added 20190902
# https://www.microsoft.com/security/blog/2016/06/14/wheres-the-macro-malware-author-are-now-using-ole-embedding-to-deliver-malicious-files/	
# https://twitter.com/enigma0x3/status/889858819232337922	
		eval {
			if (my $sec = $key->get_subkey($office_version."\\".$app."\\Security")) {
				my $pp = $sec->get_value("PackagerPrompt")->get_data();
				::rptMsg("PackagerPrompt value: ".$b);
				::rptMsg("If PackagerPrompt value = 2, OLE is disabled.");
			}
		};
# TrustRecords and Trusted Locations
		eval {
			if (my $trs = $key->get_subkey($office_version."\\".$app."\\Security\\Trusted Documents\\TrustRecords")) {
				my @vals = $trs->get_list_of_values();
				if (scalar @vals > 0) {
					::rptMsg($app." - TrustRecords");
					foreach my $v (@vals) {
						my $name = $v->get_name();
#						::rptMsg($name);
						my $data = $v->get_data();
						my ($t0,$t1) = (unpack("VV",substr($data,0,8)));
						my $t = ::getTime($t0,$t1);
						my $out_str = ::getDateFromEpoch($t)."Z: ".$v->get_name();
						my $e = unpack("V",substr($data, length($data) - 4, 4));
						$out_str .= " **Enable Content button clicked." if ($e == 2147483647);
						::rptMsg($out_str);
					}
				}
			}
			::rptMsg("");
	  };
	  
#	  eval {
#			if (my $tl = $key->get_subkey($office_version."\\".$app."\\Security\\Trusted Locations")) {
#				my @subkeys = $tl->get_list_of_subkeys();
#				if (scalar @subkeys > 0) {
#					::rptMsg($app." - Trusted Locations");
#					foreach my $s (@subkeys) {
#						::rptMsg($s->get_value("Path")->get_data());
#					}
#				}
#			}
#	  };
# File MRUs		
		eval {
			if (my $fm = $key->get_subkey($office_version."\\".$app."\\File MRU")) {
				my @vals = $fm->get_list_of_values();
				if (scalar @vals > 0) {
					::rptMsg($app." - File MRU");
					foreach my $v (@vals) {
						my $name = $v->get_name();
						next unless ($v->get_name() =~ m/^Item/);
						my ($t,$file) = processMRUValue($v->get_data());
						::rptMsg(::getDateFromEpoch($t)."Z: ".$file);
					}
					::rptMsg("");
				}
			}
		};
		
		eval {
			if (my $um = $key->get_subkey($office_version."\\".$app."\\User MRU")) {
				my @subkeys = $um->get_list_of_subkeys();
				if (scalar @subkeys > 0) {
					foreach my $s (@subkeys) {
						my @vals = $s->get_subkey("File MRU")->get_list_of_values();
						if (scalar @vals > 0) {
							::rptMsg($app."\\User MRU\\".$s->get_name()." - File MRU");
							foreach my $v (@vals) {
								next unless ($v->get_name() =~ m/^Item/);
								my ($t,$file) = processMRUValue($v->get_data());
						    ::rptMsg(::getDateFromEpoch($t)."Z: ".$file);
							}
							::rptMsg("");
						}
					}
				}
			}
		};
		
# Place MRU		
		eval {
			if (my $fm = $key->get_subkey($office_version."\\".$app."\\Place MRU")) {
				my @vals = $fm->get_list_of_values();
				if (scalar @vals > 0) {
					::rptMsg($app." - Place MRU");
					foreach my $v (@vals) {
						my $name = $v->get_name();
						next unless ($name =~ m/^Item/);
						my ($t,$file) = processMRUValue($v->get_data());
						::rptMsg(::getDateFromEpoch($t)."Z: ".$file);
					}
					::rptMsg("");
				}
			}
		};
		
		eval {
			if (my $um = $key->get_subkey($office_version."\\".$app."\\User MRU")) {
				my @subkeys = $um->get_list_of_subkeys();
				if (scalar @subkeys > 0) {
					foreach my $s (@subkeys) {
						my @vals = $s->get_subkey("Place MRU")->get_list_of_values();
						if (scalar @vals > 0) {
							::rptMsg($app."\\User MRU\\".$s->get_name()." - Place MRU");
							foreach my $v (@vals) {
								next unless ($v->get_name() =~ m/^Item/);
								my ($t,$file) = processMRUValue($v->get_data());
						    ::rptMsg(::getDateFromEpoch($t)."Z: ".$file);
							}
							::rptMsg("");
						}
					}
				}
			}
		};
	}
	
# Word Reading Locations
# It appears that the DateTime value may be recorded as local system time, with minute
# resolution (vs. sec, or micro-sec)
	eval {
		if (my $rl = $key->get_subkey($office_version."\\Word\\Reading Locations")) {
			my @subkeys = $rl->get_list_of_subkeys();
			if (scalar @subkeys > 0) {
				::rptMsg("Word - Reading Locations");
				foreach my $s (@subkeys) {
					my $path = $s->get_value("File Path")->get_data();
					my $dt   = $s->get_value("Datetime")->get_data();
					::rptMsg(::getDateFromEpoch($s->get_timestamp())."Z: ".$path." (".$dt.")");
				}
				::rptMsg("");
			}
		}
	};	
}


sub processMRUValue {
	my $str = shift;
	my ($stuff,$file) = split(/\*/,$str);
	my $t_str = (split(/\]\[/,$stuff))[1];
	$t_str =~ s/^T//;
	my $t = ::getFileTimeStr($t_str);
	return ($t,$file);
}


1;