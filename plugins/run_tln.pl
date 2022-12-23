#-----------------------------------------------------------
# run_tln
# Get contents of Run key from Software & NTUSER.DAT hives
#
# History:
#   20221222 - created TLN version of run.pl module
#
#
# copyright 2022
# Author: Philippe Baumgart, philippe.baumgart@gmail.com
#-----------------------------------------------------------
package run_tln;
use strict;

my %config = (hive          => "Software, NTUSER\.DAT",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20221222);

sub getConfig{return %config}

sub getShortDescr {
	return "[Autostart] Get autostart key contents from Software & ntuser.dat hives";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching run_tln v.".$VERSION);

	my %guess = ();
	my $hive_guess = "";
	my %guess = ::guessHive($hive);
	foreach my $g (keys %guess) {
		$hive_guess = $g if ($guess{$g} == 1);
	}

	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my @paths = ();

	if ($hive_guess eq "software") {
		@paths = ("Microsoft\\Windows\\CurrentVersion\\Run",
	             "Microsoft\\Windows\\CurrentVersion\\RunOnce",
	             "Microsoft\\Windows\\CurrentVersion\\RunServices",
	             "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
	             "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	             "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
	             "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
	             "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	             "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	             "Microsoft\\Windows\\CurrentVersion\\StartupApproved\\Run",
	             "Microsoft\\Windows\\CurrentVersion\\StartupApproved\\Run32",
	             "Microsoft\\Windows\\CurrentVersion\\StartupApproved\\StartupFolder"
	             );
	}
	elsif ($hive_guess eq "ntuser") {
		@paths = ("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	           "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
	           "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\".
	           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	           "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\".
	           "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
	           "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\StartupApproved\\Run",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\StartupApproved\\Run32",
	           "Software\\Microsoft\\Windows\\CurrentVersion\\StartupApproved\\StartupFolder"
	           );
	}
	else {}

	foreach my $key_path (@paths) {
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
      my $lw=$key->get_timestamp();

			my %vals = getKeyValues($key);
			if (scalar(keys %vals) > 0) {
        my @names=keys %vals;
        my @autoruns;
				foreach my $v (@names) {
					# ::rptMsg("  ".$v." - ".$vals{$v});
          push(@autoruns,"$v -> ".$vals{$v}.";");
				}
        ::rptMsg($lw."|REG|||Autoruns - Last Write key $key_path modified entries: ".scalar(keys %vals)." content: @autoruns");
			}
			else {
				# ::rptMsg($key_path." has no values.");
			}

			my @sk = $key->get_list_of_subkeys();
			if (scalar(@sk) > 0) {
				foreach my $s (@sk) {
          my $lw=$s->get_timestamp();
          my $subkey=$key_path."\\".$s->get_name();
					my %vals = getKeyValues($s);
          my @autoruns;
					foreach my $v (keys %vals) {
            push(@autoruns,"$v -> ".$vals{$v});
					}
          ::rptMsg($lw."|REG|||Autoruns - Last Write key $subkey modified entries: ".scalar(keys %vals)." content: @autoruns");
				}
			}
			else {
				# ::rptMsg($key_path." has no subkeys.");
			}
		}
		else {
			# ::rptMsg($key_path." not found.");
		}
	}
}


#------------------------------------------------------------------------------
#
#
#------------------------------------------------------------------------------
sub getKeyValues {
	my $key = shift;
	my %vals;

	my @vk = $key->get_list_of_values();
	if (scalar(@vk) > 0) {
		foreach my $v (@vk) {
			next if ($v->get_name() eq "" && $v->get_data() eq "");
			$vals{$v->get_name()} = $v->get_data();
		}
	}
	else {

	}
	return %vals;
}

1;
