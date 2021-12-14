#-----------------------------------------------------------
# exefile.pl
#   Checks for exefile usage and exefile open handler modification
#
# Change history
#   20211214 - Created
#
# References
#  https://twitter.com/mrd0x/status/1461041276514623491
#  https://twitter.com/swisscom_csirt/status/1461686311769759745
#  https://github.com/SigmaHQ/sigma/search?q=exefile
#
# Author: Andreas Hunkeler (@Karneades)
#-----------------------------------------------------------
package exefile;
use strict;

my %config = (hive          => "USRCLASS\.DAT,Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20211214);

sub getConfig{return %config}
sub getShortDescr {
    return "Get file associations using exefile file handler and modified open handler for exefile";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    ::logMsg("Launching exefile v.".$VERSION);
    ::rptMsg("exefile v.".$VERSION);
    ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");
    ::rptMsg("Hive ".$hive);

    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;

    my %guess = ();
    my $hive_guess = "";
    my %guess = ::guessHive($hive);
    foreach my $g (keys %guess) {
        $hive_guess = $g if ($guess{$g} == 1);
    }

    my $key_path;
    my $key;

    # SOFTWARE
    # hive is HKLM\Software\
    if ($hive_guess eq "software") {
        # file associations using exefile
        $key_path = "Classes";
        if (my $key = $root_key->get_subkey($key_path)) {
            my @sk = $key->get_list_of_subkeys();
            if (scalar @sk > 0) {
                foreach my $s (@sk) {
                    eval {
                        my $def = $s->get_value("")->get_data();
                        if ($def eq "exefile") {
                            ::rptMsg($key_path."\\".$s->get_name()." (Default) value: ".$def);
                            ::rptMsg("LastWrite Time: ".::getDateFromEpoch($s->get_timestamp())."Z");
                        }
                    };
                }
            }
        }

        # open handler exefile
        eval {
            if (my $key = $root_key->get_subkey("Classes\\exefile\\shell\\open\\command")) {
                my $def = $key->get_value("")->get_data();
                ::rptMsg("");
                ::rptMsg("Classes\\exefile\\shell\\open\\command (Default) value: ".$def);
                ::rptMsg("LastWrite Time: ".::getDateFromEpoch($key->get_timestamp())."Z");
            }
        };
    }

    # USRCLASS.DAT
    # hive is HKEY_CURRENT_USER\Software\Classes
    elsif ($hive_guess eq "usrclass") {
        # file associations using exefile
        if (my @sk = $root_key->get_list_of_subkeys()) {
            if (scalar @sk > 0) {
                foreach my $s (@sk) {
                    eval {
                        my $def = $s->get_value("")->get_data();
                        if ($def eq "exefile") {
                            ::rptMsg($key_path."\\".$s->get_name()." (Default) value: ".$def);
                            ::rptMsg("LastWrite Time: ".::getDateFromEpoch($s->get_timestamp())."Z");
                        }
                    };
                }
            }
        }

        # open handler exefile
        eval {
            if (my $key = $root_key->get_subkey("exefile\\shell\\open\\command")) {
                my $def = $key->get_value("")->get_data();
                ::rptMsg("");
                ::rptMsg("exefile\\shell\\open\\command (Default) value: ".$def);
                ::rptMsg("LastWrite Time: ".::getDateFromEpoch($key->get_timestamp())."Z");
            }
        };
    }
    else {}
}

1;
