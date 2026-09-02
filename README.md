# fido

Opens a FIDO security key on macOS and hands it to
[go-authn/fido](https://github.com/go-authn/fido) as a transport. Pure Go,
`CGO_ENABLED=0`.

```go
k, err := fido.Open(ctx)   // find the key, open it, handshake
defer k.Close()
fmt.Println(k)             // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, wink, ctap2, ctap1)
err = k.Wink(ctx)          // the key blinks: which one is this?
```

**The protocol is not here.** Framing, the handshake, the commands and every
command still to come are the same on every operating system and live in
go-authn/fido. What is macOS about a security key is four calls to IOKit, which
is what this is.

A FIDO authenticator publishes a HID interface on usage page `0xF1D0` with
64-byte reports. It opens with no entitlement and no user consent, so the whole
path is reachable through [go-macos/iokit](https://github.com/go-macos/iokit)'s
own IOKit binding: no framework, no driver, no cgo.

## One reader, started once

A second `hid.Stream` opened on a device whose first was cancelled delivers
nothing, silently — and the symptom is a key that answers the handshake and then
never again. So one reader is started when the device is opened and never
restarted.

It is registered on a run loop, so there is a moment between starting it and it
being armed. Writing during that moment loses the reply: measured at one
exchange in three. The wait is small and it is not optional — a test that
removed it reproduced the fault immediately.
