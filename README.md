[![Build Status](https://travis-ci.org/tbrowder/Net-IP-Perl6.svg?branch=master)](https://travis-ci.org/tbrowder/Net-IP-Perl6)

# Net::IP (API version 2)

This module is a beginning port of the Perl module `Net::IP` to the
`Raku` programming language.

## Notes

1. This API is not backwardly compatible with previous versions.

2. All but four functions will die if an unknown IP format is presented
for processing; those exceptions are: ip-get-version, ip-is-ipv4, ip-is-ipv6, and ip-is-ip
which return false if the argument is not known to satisfy the request. 

3. All X2ip functions require the IP version (4 or 6) to
be provided.

## Synopsis:

```
#!/usr/bin/env perl6

use Net::IP;

# manipulate IP addresses...
```

See the internal documentation in the terminal window by entering:

```
$ p6doc Net::IP
```

AUTHOR
======

Tom Browder, `<tom.browder@gmail.com>`

COPYRIGHT & LICENSE
===================

Copyright (c) 2018-2019 Tom Browder, all rights reserved.

This program is free software; you can redistribute it or modify
it under the same terms as Perl 6 itself.

See that license [here](./LICENSE).
