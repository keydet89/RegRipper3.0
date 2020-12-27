#-----------------------------------------------------------
# winscp.pl
# 
#
# Change history
#  20201227 - updated some data
#  20200525 - updated date output format
#  20140203 - created
#
# References
#
# 
# copyright 2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package winscp;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              category      => "program execution",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20201227);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's WinSCP 2 data";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

# https://metacpan.org/pod/release/GAAS/URI-1.52/URI/Escape.pm
sub uri_unescape
{
    # Note from RFC1630:  "Sequences which start with a percent sign
    # but are not followed by two hexadecimal characters are reserved
    # for future extension"
    my $str = shift;
    if (@_ && wantarray) {
        # not executed for the common case of a single argument
        my @str = ($str, @_);  # need to copy
        foreach (@str) {
            s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        }
        return @str;
    }
    $str =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg if defined $str;
    $str;
}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching winscp v.".$VERSION);
	::rptMsg("winscp v.".$VERSION); # banner
    ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Martin Prikryl\\WinSCP 2';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
# CDCache
		eval {
			::rptMsg("Configuration\\CDCache");
			my @vals = $key->get_subkey("Configuration\\CDCache")->get_list_of_values();
			foreach my $v (@vals) {
				::rptMsg("Value: ".$v->get_name());
				::rptMsg("Data : ".$v->get_data());
			}
			::rptMsg("");
		};

# \Configuration\History\RemoteTarget
		eval {
			::rptMsg("Configuration\\History\\RemoteTarget");
			my @vals = $key->get_subkey("Configuration\\History\\RemoteTarget")->get_list_of_values();
			foreach my $v (@vals) {
				::rptMsg($v->get_name()." ".$v->get_data());
				::rptMsg("(URI decode) : ".Encode::decode("utf8", uri_unescape($v->get_data())));
			}
			::rptMsg("");
		};

# \Configuration\History\LocalTarget
		eval {
			::rptMsg("Configuration\\History\\LocalTarget");
			my @vals = $key->get_subkey("Configuration\\History\\LocalTarget")->get_list_of_values();
			foreach my $v (@vals) {
				::rptMsg($v->get_name()." ".$v->get_data());
				::rptMsg("(URI decode) : ".Encode::decode("utf8", uri_unescape($v->get_data())));
			}
			::rptMsg("");
		};

#  \Configuration\Interface\Commander\LocalPanel
		
		eval {
			::rptMsg("Configuration\\Interface\\Commander\\LocalPanel");
			my $localPanelPath = $key->get_subkey("Configuration\\Interface\\Commander\\LocalPanel");
            my $data = $localPanelPath->get_value("LastPath")->get_data();
            ::rptMsg($data);
            ::rptMsg("(URI decode) : ".Encode::decode("utf8", uri_unescape($data)));
			::rptMsg("");
		};

#  \Configuration\Interface\Commander\RemotePanel
		
		eval {
			::rptMsg("Configuration\\Interface\\Commander\\RemotePanel");
			my $RemotePanelPath = $key->get_subkey("Configuration\\Interface\\Commander\\RemotePanel");
            my $data = $RemotePanelPath->get_value("LastPath")->get_data();
            ::rptMsg($data);
            ::rptMsg("(URI decode) : ".Encode::decode("utf8", uri_unescape($data)));
			::rptMsg("");
		};

#		CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}\Software\Martin Prikryl\WinSCP 2\SshHostKeys
		
		eval {
			::rptMsg("SshHostKeys");
			my @vals = $key->get_subkey("SshHostKeys")->get_list_of_values();
			foreach my $v (@vals) {
				::rptMsg("Value: ".$v->get_name());
				::rptMsg("Data : ".$v->get_data());
			}
			::rptMsg("");
		};

	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;