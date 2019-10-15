use v6;
use Test;

use Net::IP :ALL;
use Number::More :ALL;

plan 21;

# valid
ok ip-is-ipv4('10.10.10.10'), '4 octets';
ok ip-is-ipv4('10.10.10'),    '3 octets';
ok ip-is-ipv4('10.10'),       '2 octets';
ok ip-is-ipv4('10'),          '1 octet';

# not valid
nok ip-is-ipv4('a'),              'illegal chars?';
nok ip-is-ipv4('10.10.10.10.10'), 'too many octets';

# valid
is ip-get-version('1'),       '4', 'ipv4?';
is ip-get-version('1.2'),     '4', 'ipv4?';
is ip-get-version('1.2.3'),   '4', 'ipv4?';
is ip-get-version('1.2.3.4'), '4', 'ipv4?';

# not valid
is ip-get-version('a.2.3.4'),   '0', 'ipv4?';
is ip-get-version('1.2.3.4.5'), '0', 'ipv4?';

# expand
is ip-expand-address('1', 4),       '1.0.0.0';
is ip-expand-address('1.2', 4),     '1.2.0.0';
is ip-expand-address('1.2.3', 4),   '1.2.3.0';
is ip-expand-address('1.2.3.4', 4), '1.2.3.4';

# comprsee
is ip-compress-address('00.023.255', 4), '0.23.255';

# reverse
is ip-reverse-address('00.023.255', 4), '255.23.0';
is ip-reverse-address('042.00.023.255', 4), '255.23.0.42';

# conversions
my $bin = '11000011011100100101000000000000';
my $int = bin2dec $bin;
my $ip  = '195.114.80.0';
is ip-ip2int($ip, 4), $int;

is ip-int2ip($int, 4), $ip;
