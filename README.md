# Example C++ Cryptographic License Files

This is an example of how to verify and decrypt [cryptographic license files](https://keygen.sh/docs/api/cryptography/#cryptographic-lic)
in C++, using OpenSSL, Ed25519 verification and AES-256-GCM decryption.

This example implements the `aes-256-gcm+ed25519` algorithm.

## Running the example

First up, add an environment variable containing your public key:

```bash
# Your Keygen account's Ed25519 public key.
export KEYGEN_PUBLIC_KEY="e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"

# A license key.
export KEYGEN_LICENSE_KEY="E1FBA2-5488D8-8AC81A-53157E-01939A-V3"
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

Next, on macOS, ensure OpenSSL v1.1.1 is installed. If needed, install
using `homebrew`:

```bash
brew install openssl@1.1.1
```

Then compile the source using `g++`:

```bash
g++ main.cpp -o bin.out \
  -std=c++17 \
  -stdlib=libc++ \
  -lssl \
  -lcrypto \
  -I /usr/local/opt/openssl/include \
  -L /usr/local/opt/openssl/lib \
  -I include/**/*.c
```

Then run the script, passing in a path to a license file:

```bash
./bin.out /etc/keygen/license.lic
```

Alternatively, you can prefix the below command with env variables, e.g.:

```bash
KEYGEN_PUBLIC_KEY="e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788" \
  KEYGEN_LICENSE_KEY="E1FBA2-5488D8-8AC81A-53157E-01939A-V3" \
  ./bin.out examples/license.lic
```

You should see output indicating that the license file is valid, with its
decrypted dataset:

```
[INFO] Importing...
[OK] License file successfully imported!
enc=8VGeVPu...yLa9OOYufOMItzMNOdnbja+xP4RcOfRaAfHCbg==.IA+tstUP5VMxEf7F.4/SCCBbtGlsahUN1EyNylQ==
sig=y+oR9env4E44tFZHc8tDpPZL8pCyrfpatrp/wDbNAfU31YklH4xeWeShMXlN8C4bYYkIZawp1aOtNVgbC9L0BA==
alg=aes-256-gcm+ed25519
[INFO] Verifying...
[OK] License file successfully verified!
[INFO] Decrypting...
[OK] License file successfully decrypted!
[INFO] Parsing...
name=C++ Example License
key=E1FBA2-5488D8-8AC81A-53157E-01939A-V3
status=ACTIVE
last_validated_at=null
expires_at=2025-01-01T00:00:00.000Z
created_at=2022-08-05T19:27:36.492Z
updated_at=2022-08-05T19:27:36.492Z
entitlements=[FEATURE_ENTITLEMENT_C,FEATURE_ENTITLEMENT_B,FEATURE_ENTITLEMENT_A]
product=3bf34475-dfb4-42d8-a763-a2c89507f16d
policy=5ba80f5e-c3a6-4f38-bc0b-bd12053cef66
user=2068992b-f98f-4efc-95fd-687dbd0c868c
```

If the license file fails to decrypt, ensure that you're providing the correct
license key via `KEYGEN_LICENSE_KEY`. License files are encrypted with their
license's key, so an incorrect license key will fail to decrypt.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
