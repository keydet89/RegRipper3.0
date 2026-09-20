#-----------------------------------------------------------
# capaccess.pl
# Parses the Capability Access Manager ConsentStore in NTUSER.DAT:
# which applications requested access to sensitve device features,
# and when they last used them.
#
# Change history:
#   20260919 - created
#
# Notes:
#   - Only the MOST RECENT use per application is stored (start/stop),
#     this is not a full usage history.
#   - Only entries with a recorded LastUsedTimeStart/Stop are listed.
#   - LastUsedTimeStop = 0 means the device had not been released when
#     the hive was last written (still in use, or unclean shutdown).
#-----------------------------------------------------------
package capaccess;
use strict;

my %config = (hive          => "NTUSER.DAT",
              category      => "user activity",
              MITRE         => "T1123,T1125",
              hasShortDescr => 1,
              hasDescr      => 1,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20260919);

sub getConfig     { return %config }
sub getShortDescr { return "Gets Capability Access Manager ConsentStore entries (microphone, webcam, etc.)"; }
sub getDescr      { return "Lists per-application consent (Allow/Deny) and last used start/stop times for ".
                           "both packaged (UWP) and NonPackaged (Win32) apps."; }
sub getRefs       {}
sub getHive       { return $config{hive}; }
sub getVersion    { return $config{version}; }

my $VERSION = getVersion();

my $base = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";

sub pluginmain {
	my $class = shift;
	my $hive  = shift;

	::logMsg("Launching capaccess v.".$VERSION);
	::rptMsg("capaccess v.".$VERSION);
	::rptMsg("(".getHive().") ".getShortDescr());
	::rptMsg("");

	my $reg      = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key      = $root_key->get_subkey($base);

	unless ($key) {
		::rptMsg($base." not found.");
		return;
	}

	::rptMsg($base);
	::rptMsg("LastWrite time: ".fmt_time($key->get_timestamp()));
	::rptMsg("");

	my %caps = ();
	foreach my $c ($key->get_list_of_subkeys()) {
		$caps{lc($c->get_name())} = $c;
	}

	# All capabilities in alphabetical order
	foreach my $name (sort keys %caps) {
		do_capability($caps{$name});
	}
}

sub do_capability {
	my $cap   = shift;
	my $cname = lc($cap->get_name());

	::rptMsg(uc($cname));
	::rptMsg("  LastWrite: ".fmt_time($cap->get_timestamp()));

	my $gv = get_data($cap, "Value");
	::rptMsg("  Global consent: ".$gv) if (defined $gv);

	my @apps = ();
	foreach my $sk ($cap->get_list_of_subkeys()) {
		if (lc($sk->get_name()) eq "nonpackaged") {
			my $npv = get_data($sk, "Value");
			::rptMsg("  NonPackaged default consent: ".$npv) if (defined $npv);
			foreach my $np ($sk->get_list_of_subkeys()) {
				push(@apps, read_app($np, "Win32"));
			}
		}
		else {
			push(@apps, read_app($sk, "Packaged"));
		}
	}

	# Keep only entries with a recorded use
	@apps = grep { $_->{start} || $_->{stop} } @apps;

	unless (@apps) {
		::rptMsg("  No entries with recorded usage.");
		::rptMsg("");
		return;
	}

	@apps = sort { ($b->{start} <=> $a->{start}) || ($b->{lw} <=> $a->{lw}) } @apps;

	foreach my $a (@apps) {
		::rptMsg("");
		::rptMsg("  ".$a->{name}." [".$a->{type}."]");
		::rptMsg("    Consent   : ".$a->{consent}) if (defined $a->{consent});
		::rptMsg("    LastWrite : ".fmt_time($a->{lw}));
		::rptMsg("    Start     : ".fmt_time($a->{start}));

		if ($a->{stop}) {
			my $line = "    Stop      : ".fmt_time($a->{stop});
			if ($a->{start} && $a->{stop} >= $a->{start}) {
				$line .= "  (duration ".fmt_dur($a->{stop} - $a->{start}).")";
			}
			::rptMsg($line);
		}
		else {
			::rptMsg("    Stop      : 0  (still in use, or not closed cleanly)");
		}

		foreach my $o (@{$a->{other}}) {
			::rptMsg("    ".$o);
		}
	}
	::rptMsg("");
}

sub read_app {
	my ($k, $type) = @_;
	my %known = map { lc($_) => 1 } qw(Value LastUsedTimeStart LastUsedTimeStop);

	my $name = $k->get_name();
	$name =~ s/#/\\/g if ($type eq "Win32");

	my %a = (name    => $name,
	         type    => $type,
	         lw      => $k->get_timestamp(),
	         consent => get_data($k, "Value"),
	         start   => 0,
	         stop    => 0,
	         other   => []);

	my $sv = $k->get_value("LastUsedTimeStart");
	$a{start} = filetime_to_epoch($sv->get_data()) if (defined $sv);

	my $ev = $k->get_value("LastUsedTimeStop");
	$a{stop} = filetime_to_epoch($ev->get_data()) if (defined $ev);

	# Anything else present in the key is dumped rather than ignored
	foreach my $v ($k->get_list_of_values()) {
		my $vn = $v->get_name();
		next if ($known{lc($vn)});
		my $t = $v->get_type();
		my $d = $v->get_data();
		if ($t == 1 || $t == 2 || $t == 4) {
			push(@{$a{other}}, $vn." = ".$d);
		}
		else {
			push(@{$a{other}}, $vn." = [type ".$t.", ".length($d)." bytes]");
		}
	}
	return \%a;
}

sub get_data {
	my ($k, $vname) = @_;
	my $v = $k->get_value($vname);
	return undef unless (defined $v);
	return $v->get_data();
}

# REG_QWORD FILETIME (8 bytes, little endian) -> Unix epoch; 0 if unset
sub filetime_to_epoch {
	my $data = shift;
	return 0 unless (defined $data && length($data) == 8);
	my ($lo, $hi) = unpack("VV", $data);
	return 0 if ($lo == 0 && $hi == 0);
	return int((($hi * 4294967296) + $lo) / 10000000) - 11644473600;
}

sub fmt_time {
	my $t = shift;
	return "n/a" unless ($t);
	my ($s, $m, $h, $d, $mo, $y) = gmtime($t);
	return sprintf("%04d-%02d-%02d %02d:%02d:%02dZ", $y + 1900, $mo + 1, $d, $h, $m, $s);
}

sub fmt_dur {
	my $s = shift;
	return sprintf("%02d:%02d:%02d", int($s / 3600), int(($s % 3600) / 60), $s % 60);
}

1;
