# 2020-04-07
- v2.0.0
- changed API, not backwardly compatible
    + eliminate requirement to specify IP
      version when first argument is an IP in standard form
    + change function names to use "2" instead of "to"
    + add two new tests subitted as PR # 1 by `@lucasvalle` for
      `ip-ip2bin` (but modified for the new API and sub naming
      convention)
    + change module file suffix to `rakumod`
    + add Windows testing with `appveyor.yml`

# 2019-10-15
- v1.1.0
- added two functions with tests:
    + ip-int2ip
    + ip-ip2int
- deleted old docs
- added leading declarator doc for all subs


# 2018-01-24
- v1.0.0
- initial release
