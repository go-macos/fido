# fido

Talks to a FIDO security key over USB HID, in pure Go with `CGO_ENABLED=0`.

```go
k, err := fido.Open(ctx)      // finds the key, opens it, negotiates a channel
defer k.Close()
fmt.Println(k)                // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, wink, ctap2, ctap1)
err = k.Wink(ctx)             // the key blinks: which one is this?
```

It is the **second factor**. macOS already offers the first through
[go-macos/localauthentication](https://github.com/go-macos/localauthentication)
— Touch ID, a watch, the device passcode — and those answer *is the person at
this machine the one who unlocked it?* A security key answers a different
question: *is the thing they carry present, right now?* Multi-factor means
asking both and getting two independent answers.

## Why this exists

A FIDO authenticator publishes a HID interface on usage page `0xF1D0` with
64-byte reports. It opens with no entitlement and no user consent, so the whole
path is reachable from Go — through
[go-macos/iokit](https://github.com/go-macos/iokit)'s own IOKit binding, with
no framework, no driver and no cgo.

In pure Go, client-side, there was nothing to reuse. The reference
implementation of the field is Yubico's own **libfido2**, written in C; its one
serious Go binding wraps it through cgo and has not moved in ten months. The
pure-Go candidates are small and young. So this reads libfido2 and the CTAP
specification as **documentation**, and owns the code.

## What reading the reference caught

Two faults that testing against a key would not have found, because a key
answers a short ping the same either way:

- **`CTAPHID_KEEPALIVE` is not an answer.** A key waiting for a finger sends one
  about every hundred milliseconds for as long as the person takes. A reader
  that returns the first complete message hands back a status byte instead of
  the reply — and does it early, so it looks like the key talking nonsense.
- **The message limit is the framing's, not the length field's.** Two length
  bytes would allow 65535; the framing reaches 7609, because past that the
  sequence numbers run into the high bit and a key reads them as the start of a
  new message.

## What is here

Enumeration, the CTAPHID handshake, channel negotiation, capabilities, ping and
wink — with the framing portable, tested to 100% off macOS, and the transport
behind a seam so a key that refuses, a key that stalls and a key that keeps
saying it is busy can all be driven from a test.

CBOR, `makeCredential`, `getAssertion` and `ClientPIN` are not here yet.
