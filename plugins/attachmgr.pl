#-----------------------------------------------------------
# attachmgr.pl
# The Windows Attachment Manager manages how attachments are handled,
# and settings are on a per-user basis.  Malware has been shown to access
# these settings and make modifications.
#
# Category: Malware
#
# Change history
#  20200525 - updated date output format, removed alertMsg() functionality
#  20130425 - added alertMsg() functionality
#  20130117 - created
#
# References
#  http://journeyintoir.blogspot.com/2010/10/anatomy-of-drive-by-part-2.html
#  http://support.microsoft.com/kb/883260
#  http://blog.handlerdiaries.com/?p=703
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package attachmgr;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200525);

sub getConfig{return %config}
sub getShortDescr {
	return "Checks user's keys that manage the Attachment Manager functionality";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	my @temps;
	
	::logMsg("Launching attachmgr v.".$VERSION);
	::rptMsg("attachmgr v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	
	my @attach = ('Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations',
	             'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments');
	
	foreach my $key_path (@attach) {
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
			my @vals = $key->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) { 
					my $name = $v->get_name();
					my $data = $v->get_data();
					::rptMsg(sprintf "%-15s  %-6s",$name,$data);
				}
			}
			else {
				::rptMsg($key_path." has no values.");
			}
		}
		else {
			::rptMsg($key_path." not found.");
		}
		::rptMsg("");
	}
}

1;