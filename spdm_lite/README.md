# SPDM-Lite

This library implements SPDM 1.2 secure sessions.

This is not an official Google product.

## Build

### Install Dependencies

On Debian and Ubuntu install the following packages:

```
$ sudo apt install libmbedtls-dev libtss2-dev cmake
```

Note that mbedtls and libtss2 are only needed for tests. The core spdm-lite
library does not take a direct dependency on any external libraries.

### Build and run tests

```
$ cmake -B build
$ cmake --build build
$ ctest --test-dir build
```

## User guide

### Requesters

Requesters are expected to call `spdm_establish_session`, and then
`spdm_dispatch_app_request` for each subsequent message sent over the secure
session. Requesters can tear down the session by calling `spdm_end_session`.

Requesters are expected to initialize and provide an `SpdmDispatchRequestCtx`,
which provides both a function pointer used to dispatch messages to the
Responder, as well as scratch memory used for staging encrypted requests and
responses. The scratch memory should be as large as
`(max request or response size + SPDM_SECURE_MESSAGE_OVERHEAD)`

See `samples/requester_app.c` which illustrates how this can be done.

### Responders

Responders are expected to call `spdm_dispatch_request` upon receipt of an SPDM
request. The transport binding used by the Responder must indicate whether or
not the given SPDM request is encrypted.

In addition, Responders are expected to provide a callback function of type
`spdm_app_dispatch_request_fn`, which will be invoked upon receipt of a
vendor-defined command sent within an established secure session.

This implementation currently only supports one active session at a time.

See `samples/responder_app.c` which illustrates how this can be done.

### Mutual authentication

This implementation requires mutual authentication. Certificate exchange is out
of scope. As SPDM 1.2 currently does not support a mechanism for exchanging raw
public keys, this implementation provides a pair of custom vendor-defined
commands for this purpose. See `common/vendor_defined_pub_key.h` for the message
structure.

### Crypto

Requesters and Responders are expected to implement an instance of
`SpdmCryptoSpec`.

These instances contain function pointers for low-level crypto primitives, as
well as serialization and deserialization functions for asymmetric public keys.

Users should override `SPDM_MAX_SERIALIZED_ASYM_PUB_KEY_SIZE` in
`include/spdm_lite/common/config.h` when providing a public key serialization
routine.

### Timing

This library does not implement timing-related functionality.

## Parsers

This library parses SPDM messages using
[EverParse](https://project-everest.github.io/everparse/). See
`everparse/SPDM.3d` for a description of each message, expressed in EverParse's
[Dependent Data Description language](https://project-everest.github.io/everparse/3d-lang.html).
`everparse/build.sh` will generate the parser functions.
`everparse/SPDMWrapper.{h,c}` contains manually-created wrapper functions to
better integrate with the type system used in spdm-lite.

## TODO

*   Endian conversion
*   Error codes / debug messages
*   Max message size enforcement
*   Customizable algorithm negotiation routine
*   GET_CERTIFICATE / KEY_UPDATE / HEARTBEAT / CHUNK_SEND etc.
