# Stegosafe — CLI steganography tool

This crate is a minimal steganography CLI built on `stegosafe-crypto`.

Usage examples:

Embed a payload into a cover image:

```bash
cargo run -p stegosafe -- embed --cover cover.png --payload secret.bin --output out.png --secret "my shared secret" --context "session-1"
```

This writes:
- `out.png` — the stego image
- `out.meta` — metadata containing `nonce:<hex>` and `mac:<hex>` used to verify integrity

Extract a payload using metadata file:

```bash
cargo run -p stegosafe -- extract --stego out.png --output recovered.bin --secret "my shared secret" --context "session-1"
```

Or provide nonce explicitly (hex):

```bash
cargo run -p stegosafe -- extract --stego out.png --output recovered.bin --secret "my shared secret" --context "session-1" --nonce <hexnonce>
```
