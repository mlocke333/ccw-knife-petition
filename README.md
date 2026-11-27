# CCW automatic knife petition

Grassroots signature page for a limited California CCW exception for automatic knives.

The page is the Cloudflare Worker `ccw-knife-petition` at https://ccwknife.ldcybersystems.com/. The form posts to `/api/sign` on that Worker. Each signature is encrypted with AES-256-GCM before it is written to the D1 database `ccw-knife-petition`. The database stores the ciphertext, a random IV, and an HMAC of the email so the same address cannot sign twice. Names, emails, cities, and comments are not stored in plaintext.

`ENCRYPTION_KEY` and `ADMIN_TOKEN` are Worker secrets. Local copies live in `.dev.vars`, which is not committed. Losing both the Worker secret and that file makes stored signatures unreadable.

To download decrypted signatures:

```bash
node scripts/export-signatures.mjs
```

That writes `signatures.json` in this directory. The file is gitignored.
