# Stegosafe — CLI steganography tool

This project is a minimal steganography CLI built on `stegosafe-crypto`.

Usage examples:

Create a passphrase file first:

```bash
printf '%s\n' 'my shared secret' > secret.txt
```

Embed a payload into a cover image:

```bash
cargo run -p stegosafe -- embed --cover cover.png --payload secret.bin --output out.png --secret-file secret.txt --context "session-1"
```

This writes:
- `out.png` — the stego image
- `out.meta` - authenticated JSON metadata containing the KDF salt, session nonce, embedding format, encrypted payload length, and MAC

Extract a payload using metadata file:

```bash
cargo run -p stegosafe -- extract --stego out.png --output recovered.bin --secret-file secret.txt --context "session-1"
```

Extraction requires the `.meta` file. Missing or tampered metadata fails closed.
