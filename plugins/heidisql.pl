package heidisql;
use strict;
#-----------------------------------------------------------
# heidisql.pl
# 
#
# Change history
#  20201227 - created
#
# References
# N/A
# 
# Author: Hyun Yi @hyuunnn
#-----------------------------------------------------------
my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "program execution",
              version       => 20201227);

sub getConfig{return %config}
sub getShortDescr {
    return "Gets user's heidisql data"
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    ::logMsg("[*] Launching heidisql v.".getVersion());
    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;
    my $key;
    my $keyname;
    my @paths;

    if ($key = $root_key->get_subkey("SOFTWARE\\HeidiSQL")) {
        ::rptMsg("[-] SOFTWARE\\HeidiSQL");
        ::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
        ::rptMsg("LastActiveSession : ".$key->get_value("LastActiveSession")->get_data());
        ::rptMsg("LastUsageStatisticCall : ".$key->get_value("LastUsageStatisticCall")->get_data());
        my @vals = $key->get_list_of_values();
        if (scalar(@vals) > 0) {
            foreach my $v (@vals) {
                my $name = uc($v->get_name());
                if ($name =~ m/SQLFILE([0-9]+)/) {
                    ::rptMsg($v->get_name()." : ".$v->get_data());
                }
            }
        }
        ::rptMsg("ExportSQL_Filenames : ".$key->get_value("ExportSQL_Filenames")->get_data());
    } 
    else {
        ::rptMsg("[-] SOFTWARE\\HeidiSQL not found.");
    }

    my $key_path = "SOFTWARE\\HeidiSQL\\Servers";

    if ($key = $root_key->get_subkey($key_path)) {

        my @sk = $key->get_list_of_subkeys();
        if (scalar @sk > 0) {
            foreach my $k (@sk) {
                push(@paths, $k->get_name);
            }
        }

        foreach my $name (@paths) {
            if ($key = $key->get_subkey($name)) {
                ::rptMsg("[-] ".$name);
                ::rptMsg("Host : ".$key->get_value("Host")->get_data());
                ::rptMsg("Port : ".$key->get_value("Port")->get_data());
                ::rptMsg("User : ".$key->get_value("User")->get_data());
                ::rptMsg("LastConnect : ".$key->get_value("LastConnect")->get_data());
                ::rptMsg("lastUsedDB : ".$key->get_value("lastUsedDB")->get_data());
                ::rptMsg("SessionCreated : ".$key->get_value("SessionCreated")->get_data());
            }

            if ($key = $key->get_subkey("QueryHistory")) {
                ::rptMsg("[-] QueryHistory");
                my @vals = $key->get_list_of_values();
                if (scalar(@vals) > 0) {
                    foreach my $v (@vals) {
                        ::rptMsg($v->get_name()." : ".$v->get_data());
                    }
                }
            }
        }


    }
    else {
        ::rptMsg("[-] ".$key_path." not found.");
    }
    ::rptMsg("");
}