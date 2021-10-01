#-----------------------------------------------------------
# iconlayouts.pl
# 
#
# Change history
#  20211001 - created
#
# References
# https://github.com/kacos2000/Win10/blob/master/Desktop_IconLayouts.pdf
# 
# Author: Hyun Yi @hyuunnn
#-----------------------------------------------------------
package iconlayouts;
use strict;
use Encode::Unicode;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              osmask        => 22,
              category      => "User Activity",
              version       => 20211001);

sub getConfig{return %config}
sub getShortDescr {
    return "Shell/Bag/1/Desktop - Iconlayouts"
}

sub getDescr{}
sub getRefs {
    return "https://github.com/kacos2000/Win10/blob/master/Desktop_IconLayouts.pdf"
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    ::logMsg("[*] Launching iconlayouts v.".getVersion());
    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;
    my $key_path = 'Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop';

    my $key;
    if($key = $root_key->get_subkey($key_path)) {
        printData($key->get_value("IconLayouts")->get_data());
    }
}

sub printData {
    my $data = shift;
    my $idx = 0x18;

    my $count = unpack("C", substr($data, $idx, 2));
    $idx += 8;

    ::rptMsg("[*] Desktop file Lists");
    foreach my $i (1..$count) {
        my $length = unpack("C", substr($data, $idx, 2));
        $idx += 8;

        my $value = substr($data, $idx, $length*2);
        $idx += $length*2;
        ::rptMsg(_uniToAscii($value));
    }
}

sub _uniToAscii {
    my $str = $_[0];
    Encode::from_to($str, 'UTF-16LE', 'utf8');
    $str = Encode::decode_utf8($str);
    return $str;
}