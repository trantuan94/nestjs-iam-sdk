#!/usr/bin/env node
/**
 * Refreshes contract/authorize.openapi.json from nestjs-iam-service's committed
 * swagger.json — the parts of it this SDK depends on, and nothing else.
 *
 *   npm run contract:update                       # ../nestjs-iam-service/swagger.json
 *   npm run contract:update -- path/to/swagger.json
 *   npm run contract:update -- https://raw.githubusercontent.com/<owner>/nestjs-iam-service/<ref>/swagger.json
 *
 * Then run `npm test`: test/contract.spec.ts fails if the SDK's types no longer
 * match. Commit the snapshot with the change that adapts to it.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = process.argv[2] ?? resolve(here, '../../nestjs-iam-service/swagger.json');

const text = /^https?:\/\//.test(source)
  ? await (await fetch(source)).text()
  : await readFile(source, 'utf8');
const document = JSON.parse(text);

const path = document.paths?.['/auth/authorize'];
if (!path?.post) throw new Error(`${source} has no POST /auth/authorize`);

const SCHEMAS = ['AuthorizeRequestDto', 'AuthorizeResponseDto', 'ErrorResponseDto'];
const schemas = Object.fromEntries(
  SCHEMAS.map((name) => {
    const schema = document.components?.schemas?.[name];
    if (!schema) throw new Error(`${source} has no schema ${name}`);
    return [name, schema];
  }),
);

let ref = 'unknown';
if (!/^https?:\/\//.test(source)) {
  try {
    ref = execFileSync('git', ['-C', dirname(source), 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    // not a git checkout; the source path is recorded instead
  }
}

const snapshot = {
  'x-source': { document: source.startsWith('http') ? source : 'nestjs-iam-service/swagger.json', ref },
  info: { title: document.info?.title, version: document.info?.version },
  paths: { '/auth/authorize': path },
  components: { schemas },
};
const out = resolve(here, '../contract/authorize.openapi.json');
await writeFile(out, `${JSON.stringify(snapshot, null, 2)}\n`);
console.log(`contract updated from ${source} (${ref})`);
