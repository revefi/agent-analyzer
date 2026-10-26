# Upload contract

`upload_manifest.schema.json` is a verbatim copy of the analyzer server's upload manifest schema,
format version 1. It is the contract the CLI's manifest is tested against
(`cli/test/contract.test.ts`).

Do not edit it here. When the server publishes a new format version, copy the new schema over
this file, update the hash below, and update the CLI in the same change.

```text
sha256  37f804f36a2410f5eece8a92056bb034214d6f44d1b28985043e49b4b8d9adac
```
