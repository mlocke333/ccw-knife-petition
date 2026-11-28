# CCW automatic knife petition

Grassroots signature page for a limited California CCW exception for automatic knives.

The page is the Cloudflare Worker `ccw-knife-petition` at https://ccwknife.ldcybersystems.com/. The form posts to `/api/sign` on that Worker. Each signature is a row in the D1 database `ccw-knife-petition`. Cloudflare encrypts that database at rest.

Read the signatures in the Cloudflare dashboard:

https://dash.cloudflare.com/333c045b18d7189ea99fba8df9143717/workers/d1/databases/c245b975-bea2-48c6-8beb-cfe84d8422ba

```sql
SELECT created_at, name, email, city, county, zip, ccw_holder, comment
FROM signatures
ORDER BY created_at;
```
