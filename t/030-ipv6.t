use v6;
use Test;

use Net::IP :ALL;
use Number::More :ALL;

plan 22;

# valid
ok ip-is-ipv6 '1::1';
ok ip-is-ipv6 '1:a:c::1';
ok ip-is-ipv6 '::1';

# not valid
nok ip-is-ipv6 '1::1::1';
nok ip-is-ipv6 ':1';
nok ip-is-ipv6 '1:';
nok ip-is-ipv6 '1:2:3:4:5:6:7:8:9';
nok ip-is-ipv6 '1:a:c:1';

# valid
is ip-get-version('1::1'),     '6';
is ip-get-version('1:a:c::1'), '6';
is ip-get-version('::1'),      '6';

# not valid
is ip-get-version('a.2.3.4'),   '0';
is ip-get-version('1.2.3.4.5'), '0';

# expand
is ip-expand-address('1::1'),
  '0001:0000:0000:0000:0000:0000:0000:0001';

is ip-ip2bin('1::1'),
  '00000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001';

is ip-bin2ip('00000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001', 6),
  '0001:0000:0000:0000:0000:0000:0000:0001';

# compress
is ip-compress-address('0001:0000:0000:0000:0000:0000:0000:0001'),
  '1::1';

is ip-compress-address('0001:00e0:0000:0000:0000:0000:0000:0001'),
  '1:e0::1';

# reverse
is ip-reverse-address('0001:00e0:0000:0000:0000:0000:0000:0001'),
  '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.0.0.1.0.0.0';

is ip-reverse-address('1:00e0::0001'),
  '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.0.0.1.0.0.0';

# conversions
my $bin = '11011110101011011011111011101111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
my $int = bin2dec $bin;
my $ip  = 'dead:beef::'; # short version
my $ip2 = ip-expand-address $ip;
is ip-ip2int($ip), $int;

is ip-int2ip($int, 6), $ip2;
