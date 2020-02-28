# Yubikey enabled secret sharing (`yess`)

`yess` enables splitting secrets into shares using a threshold schema that requires e.g. 3 out of 4 shares to successfully recombine. These shares are furthermore encrypted using the [PIV](https://en.wikipedia.org/wiki/FIPS_201) interface of [compatible](https://www.yubico.com/products/compare-products-series/) Yubikeys. This enables workflows where shares are protected by physical devices that are hard to clone and can be protected through additional physical security measures (e.g. safes). Since only a subset of devices is neccessary to recombine, operations are still possible even if a devices breaks or get lost.

**DO NOT USE THIS TOOL FOR ++ANY++ PURPOSE YET - REVIEW(S) ARE STILL PENDING**

## Workflow example

Three Yubikeys _yk1_, _yk2_ and _yk3_ have been prepared in advance (using the `yubikey-piv-tool`, `ykman` or the Yubikey Manager GUI) by

- enabling the PIV interface (enabled by default) and creating "Key Management" (encryption) certificates (currently only ECC keys are supported)
- optionally [disabling the OTP](https://support.yubico.com/support/solutions/articles/15000006440-accidentally-triggering-otp-codes-with-your-nano-yubikey) interface (enabled by default) in order to prevent accidently "typing" in OTP codes - this (or USB extension cords) should be considered when dealing with very small (e.g. USB-C) form factors or "nano" keys

### Splitting

Next a secret is piped into `yess` like this: `echo my-secret | yess split --parts 3 --threshold 2 > result.json`. `yess` now asks the user to insert the Yubikeys one-by-one and enter their respective PINs. After this succeeds, `yess` outputs a metadata file like this on `stdout`:

```
{
"parts": [
  {
    "device": "A",
    "expiry": "2021-02-25T00:00:00Z",
    "issuer": "CN=acme inc",
    "publicKey": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECgXCraDGX1xN8HfvOpGAPY2Jmp56bRBWLE0vIVxk4CsyDnPyiWF3Vq3gI1KsWaMZxyXRk+mUprPbbu32pUEv4/a9b7zYwte8lsL4n9DS92EKZbkqxSEa4Xd2kI2klZlz",
    "serial": 1,
    "share": "U/VNWIT1+ZqYwbwanJ/5FZITpP2xBQM2QQilK7uunh2K6gSRvcxnmFNtShebbh+9Xxd4dPZ+U3aqKx3IT3FSFtZL",
    "subject": "CN=mr. a"
  },
  {
    "device": "B",
    "expiry": "2021-02-26T00:00:00Z",
    "issuer": "CN=bcme inc",
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs8WjfkQMzZaaCj7UltEtzLDJwdox1QhFPMQBDqJN0EhT/egUfo+2gC4ibWGpH8PsKrJKJP+F3OIQcX0ZTbUNVg==",
    "serial": 2,
    "share": "k9YI2Yzpr5gTYtuyu1giI5oeWSmFSOVxx82QinbCJJFRANuN4TvBKyQHsedca2ZrAYGm59ci1ZeE1A3F7MVP",
    "subject": "CN=ms. b"
  },
  {
    "device": "C",
    "expiry": "2021-02-27T00:00:00Z",
    "issuer": "CN=ccme inc",
    "publicKey": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWW5+qZV4rgceOFHw/M/kxpE/5DrQyben5vDwM0cxNCt2dpoNIksQloDnrE58gVVl0kKl5zXQ7zUNYsWLr//rveBHiFEVcYhZOiahMELPa0QqPWJR0+50kCxJ3G9btKbX",
    "serial": 3,
    "share": "6aWlG3fx2dpf6AeSnX7UMlFkdF0aBB6+nMRubqTCZloXvIXT+2spOu0nLs4EcOL3ChhUwv9wJodssUrI",
    "subject": "CN=mrs. c"
  }
],
"threshold": 2
}
```

### Combining

Next the metadata is piped into `yess` like this: `cat result.json | yess combine`. `yess` presents the list of candidate devices and asks the user to insert at least 2 Yubikeys (= the threshold from above) out of this list one-by-one and enter their respective PINs. After this succeeds, `yess` outputs the secret on `stdout`.

## Protocol details

Operating on

- secret _s_
- parts _p_=3
- threshold _t_=2

### ECC keys

Currently only ECC keys are supported.

#### Splitting

- Apply SHA3-256 hash on _s_ and concat resulting hash _h_ to _s_, yielding _sh_
- Split _sh_ into _p_ parts using [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) with _p_ and _t_, yielding _p_ times _shp_
- For each _shp_
  - generate ephemeral ECC keypair _ek_ matching the curve of the device public key
  - perform key exchange with _ek_ and device public key, yielding shared ephemeral key _sk_
  - derive a 32-bit key _dk_ from _sk_ using SHA3-256
  - encrypt _shp_ using a NacL secretbox, with _dk_ as key and zero as nonce (since keys are ephemeral anyways) yielding _shpe_
  - store _shpe_ and the public key _pk_ of _ek_ in metadata to allow for later recovery

#### Combining

- For each _shpe_
  - recover _sk_ by calling `Decrypt` on device using _pk_
  - derive _dk_ from _sk_ using SHA3-256
  - decrypt _shpe_ using a NacL secretbox, with _dk_ as key and zero as nonce (since keys are ephemeral anyways) yielding _shp_
- As soon as _t_ has been passed, attempt a Shamir Secret Sharing recovery and continue with the loop if that fails
- Split _sh_ into _s_ and _h_ and verify that the SHA3-256 hash of _s_ is equal to _h_ and continue with loop if that fails

If no failure occurs, the secret _s_ has been recovered.
