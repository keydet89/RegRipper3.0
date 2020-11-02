#-----------------------------------------------------------
# outlook_homepage.pl
#  Plugin for Registry Ripper 3.0
#   Analysis provided by FireEye indicates that attackers can
#   abuse Outlook's feature to set a homepage which loads a
#   malicious website which allows persistence and a vector for
#   attack.  This method exploits vulnerabilities outlined in 
#   CVE-2017-11774
#  
# Change history
#   20201102 - created
#
# References
#   https://www.fireeye.com/blog/threat-research/2019/12/breaking-the-rules-tough-outlook-for-home-page-attacks.html
#
# Copyright 2020 MrHobbits.com (https://www.mrhobbits.com)
# Author: Mr. Hobbits mrhobbits@mrhobbits.com
#-----------------------------------------------------------
package outlook_homepage;
use strict;

my %config = (hive          => "NTUSER\.DAT, Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "malware",
              version       => 20201002);

my $VERSION = getVersion();

sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {
	return "Retrieve values set to attack Outlook WebView Homepage";
}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching outlook_homepage v.".$VERSION);
  ::rptMsg("outlookhomepage v.".$VERSION);
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");   
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	# I know the code is messy. Who cares, it works, and I don't know Perl.
	# If anyone looking at source code of plugins reads this (and isn't H. Carvey)
	# if you don't like it, write your own plugin! 
	#
	# This part looks for the keys for the inbox
	my $key= "URL";
	my $key_name = "Inbox";
	my @paths = ("Software\\Microsoft\\Office\\9.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\10.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\11.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\12.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\13.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\14.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\15.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\16.0\\Outlook\\WebView\\".$key_name,
                     "Software\\Microsoft\\Office\\17.0\\Outlook\\WebView\\".$key_name);
	
	# check to see if the hive has the URL set for the WebView option
	::rptMsg("Looking for webview homepage modifications. If this value is pointing\n".
		 "to a URL outside the corporate domain it may be a malicious site.");
	foreach my $key_path (@paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
			::rptMsg("");

			my @vals = $key->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					::rptMsg("  ".$v->get_name()." : ".$v->get_data());
				}
			} else {
				::rptMsg($key_path.$key." found, has no values.");
			}
		}
		else {
			# commented out because we don't need it cluttering the screen
			#::rptMsg($key_path.$key." not found.");
		}
	} 

	############ 
	# Security #
	############
	#
	# This part looks for the keys for the security
	::rptMsg("\nLooking for key values associated with security.\nIf you see:\n".
		"[Example]  EnableRoamingFolderHomepages : 1\n".
		"[Example]  NonDefaultStoreScript : 1\n".
		"[Example]  EnableUnsafeClientMailRules : 1\n".
		"You may have a security vulnerability that allows attackers to hijack the URL\n");
	my $key= ""; 
	my $key_name = "Security";
	my @paths = ("Software\\Microsoft\\Office\\9.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\10.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\11.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\12.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\13.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\14.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\15.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\16.0\\Outlook\\".$key_name,
                     "Software\\Microsoft\\Office\\17.0\\Outlook\\".$key_name);
	
	# check to see if the hive has the URL set for the WebView option
	foreach my $key_path (@paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
			::rptMsg("");

			my @vals = $key->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					::rptMsg("  ".$v->get_name()." : ".$v->get_data());
				}
			} else {
				::rptMsg($key_path.$key." found, has no values.");
			}
		}
		else {
			# commented out because we don't need it cluttering the screen
			#::rptMsg($key_path.$key." not found.");
		}
	} 
}
1;
