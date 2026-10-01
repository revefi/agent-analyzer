import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schema = JSON.parse(
  readFileSync(new URL("../../contract/upload_manifest.schema.json", import.meta.url), "utf8"),
);
const ajv = new Ajv2020({ allErrors: true });
addFormats.default(ajv);

export const validateManifest = ajv.compile(schema);
