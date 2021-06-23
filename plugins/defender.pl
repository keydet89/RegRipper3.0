#-----------------------------------------------------------
# defender.pl
#   
# Get Windows Defender Exclusion settings from the Software hive
#
# Change history
#   20210623 - updated for GPO keys and improve output format
#   20200427 - updated output date format
#   20200409 - updates
#   20191202 - updated to include Defender settings affected by Clop ransomware
#   20191018 - created
#
# References
#   *Observed a case where a folder containing malware was added to Exclusions, causing
#    Defender to bypass and not detect/quarantine the malware
#   https://www.bleepingcomputer.com/news/security/clop-ransomware-tries-to-disable-windows-defender-malwarebytes/
#
# Copyright 2019-2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com, Andreas Hunkeler (@Karneades)
#-----------------------------------------------------------
package defender;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "configuration",
              version       => 20200427);

my $VERSION = getVersion();

sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {
    return "Get Windows Defender settings";
}
sub getRefs {}

sub pluginmain {
    my $class = shift;
    my $hive = shift;

    ::logMsg("Launching defender v.".$VERSION);
    ::rptMsg("defender v.".$VERSION);
    ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");   
    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;
    my $key;
    my $path_str = "Microsoft\\Windows Defender";
    my @key_paths = ($path_str, "Policies\\".$path_str);

    foreach my $key_path (@key_paths) {
        if ($key = $root_key->get_subkey($key_path)) {
            ::rptMsg("Key path: ".$key_path);
            ::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
            ::rptMsg("");

            foreach my $i ("Paths","Extensions","Processes","TemporaryPaths","IpAddresses") {
                ::rptMsg("Key path: ".$key_path."\\Exclusions\\".$i);
                eval {
                    if (my $excl = $key->get_subkey("Exclusions\\".$i)) {
                        my @vals = $excl->get_list_of_values();
                        if (scalar @vals > 0) {
                            ::rptMsg("Exclusions\\".$i." key LastWrite time: ".::getDateFromEpoch($excl->get_timestamp())."Z");
                            foreach my $v (@vals) {
                                ::rptMsg(sprintf "  %-50s %2d",$v->get_name(),$v->get_data());
                            }
                            ::rptMsg("");
                        }
                    }
                };
                ::rptMsg("");
            }
        }
        else {
            ::rptMsg($key_path." not found.");
        }
        # Check Tamper Protection
        if ($key = $root_key->get_subkey($key_path)) {

            eval {
                my $tamp = $key->get_subkey("Features")->get_value("TamperProtection")->get_data();
                ::rptMsg("Key path: ".$key_path."\\Features");
                ::rptMsg("TamperProtection value = ".$tamp);
                ::rptMsg("If TamperProtection value = 1, it's disabled");
                ::rptMsg("");
            };
        }

        if ($key = $root_key->get_subkey($key_path)) {
            eval {
                if (my $as = $key->get_value("DisableAntiSpyware")->get_data()) {
                    ::rptMsg("DisableAntiSpyware value = ".$as) if ($as == 1);
                    ::rptMsg("");
                }
            };

            if (my $block = $key->get_subkey("MpEngine")) {
                eval {
                    if (my $b = $block->get_value("MpCloudBlockLevel")->get_data()) {
                        ::rptMsg("Key path: ".$key_path."\\MpEngine");
                        ::rptMsg("LastWrite Time: ".::getDateFromEpoch($block->get_timestamp())."Z");
                        ::rptMsg("MpEngine\\MpCloudBlockLevel value = ".$b);
                        ::rptMsg("");
                    }
                };
            }

            if (my $spy = $key->get_subkey("Spynet")) {
                eval {
                    if (my $s = $spy->get_value("SpynetReporting")->get_data()) {
                        ::rptMsg("Key path: ".$key_path."\\Spynet");
                        ::rptMsg("LastWrite Time: ".::getDateFromEpoch($spy->get_timestamp())."Z");
                        ::rptMsg("Spynet\\SpynetReporting value = ".$s);
                        ::rptMsg("");
                    }
                };

                eval {
                    if (my $samp = $spy->get_value("SubmitSamplesConsent")->get_data()) {
                        ::rptMsg("Spynet\\SubmitSamplesConsent value = ".$samp);
                        ::rptMsg("");
                    }
                };
            }

            if (my $t = $key->get_subkey("Real-Time Protection")) {
                my @vals = ("DisableBehaviorMonitoring","DisableOnAccessProtection","DisableRealtimeMonitoring",
                    "DisableScanOnRealtimeEnable");
            ::rptMsg("Key path: ".$key_path."\\Real-Time Protection");
            ::rptMsg("LastWrite Time: ".::getDateFromEpoch($t->get_timestamp())."Z");        
                foreach my $val (@vals) { 
                    eval {
                        my $v = $t->get_value($val)->get_data();
                        ::rptMsg($val." value = ".$v);
                    };
                }
                ::rptMsg("");
            }
        }
        else {
#            ::rptMsg($key_path." not found.");
        }
    }
}

1;
