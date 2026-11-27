import { readFileSync, writeFileSync } from "node:fs";

const vars = Object.fromEntries(
  readFileSync(new URL("../.dev.vars", import.meta.url), "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const index = line.indexOf("=");
      return [line.slice(0, index), line.slice(index + 1)];
    }),
);

const response = await fetch("https://ccwknife.ldcybersystems.com/api/export", {
  headers: { Authorization: `Bearer ${vars.ADMIN_TOKEN}` },
});

if (!response.ok) {
  console.error(`export failed: ${response.status}`);
  process.exit(1);
}

const out = process.argv[2] || "signatures.json";
writeFileSync(out, await response.text());
console.log(`wrote ${out}`);
