This project provides an HMAC implementation based on BLAKE.
In particular, this project provides

  * HMAC-BLAKE-224
  * HMAC-BLAKE-256
  * HMAC-BLAKE-384
  * HMAC-BLAKE-512

in addition to the regular BLAKE functions.

[BLAKE](http://131002.net/blake/) is a SHA-3 candidate hash algorithm.
HMAC is specified by [RFC 2104](https://tools.ietf.org/html/rfc2104).

# Usage

Build the hash functions:

    $ make

Test them:

    $ echo -n "Hello World" | ./bin/blake512hmac secretkey
    cc0f6967c2377ce286f12392339d91af453e1e3979c35cdd45c5c31ab3fd64d4a998e00b5c703b03c16fc3e95904c4ff3de2ac5861066d8047338ce289532cbd

    $ echo -n "Hello World" | ./bin/blake384sum
    8e0b9432b32a4a6b8fb5a922a00add624ed4185267da30274c573149fa133f8677ed4a4a828aca0cc02257095144a312

# TODO

* PBKDF2 based on BLAKE.
