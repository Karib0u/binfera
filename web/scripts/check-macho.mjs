// Run after npm run build:wasm. Exercise the browser engine without a UI.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import createBinfera from '../src/wasm/binfera.js';

const fixtures = new URL('../../binfera/tests/fixtures/', import.meta.url);
const assets = new URL('../src/wasm/', import.meta.url);
for (const [file, args, expected] of [
  ['macho/thin-x86_64-exe', ['--decompile-function', '0x100000510', '--json'], 'malloc(0x10)'],
  ['macho/thin-arm64-exe', ['--decompile-function', '0x1000004f8', '--json'], 'malloc(0x10)'],
  ['macho/fat-x86_64-arm64-exe', ['--arch', 'arm64', '--decompile-all'], 'malloc(0x10)'],
  ['macho_metadata/objc-arm64', ['--decompile-all'], 'objc_msgSend_add_'],
  ['macho/fat-x86_64-arm64-exe', ['--arch', 'arm64', '--dump-features'], 'aarch64'],
]) {
  const output = [], errors = [];
  const engine = await createBinfera({
    locateFile: name => fileURLToPath(new URL(name, assets)),
    noInitialRun: true,
    print: text => output.push(text),
    printErr: text => errors.push(text),
  });
  engine.FS.writeFile('/sample', fs.readFileSync(new URL(file, fixtures)));
  try { engine.callMain(['/sample', ...args]); }
  catch (error) { if (error.status !== 0) throw error; }
  if (!output.join('\n').includes(expected)) {
    throw new Error(`${file}: ${output.join('\n')}\n${errors.join('\n')}`);
  }
  console.log(`${file} ${args.join(' ')}: passed`);
}

// The browser obtains all binary metadata through this CLI surface in an inspection worker.
for (const [file, arch] of [
  ['macho/thin-x86_64-exe', 'x64'],
  ['macho/thin-arm64-exe', 'aarch64'],
  ['macho/fat-x86_64-arm64-exe', 'x64'],
  ['elf64_sysv/dynamic.elf', 'x64'],
]) {
  const output = [];
  const engine = await createBinfera({
    locateFile: name => fileURLToPath(new URL(name, assets)),
    noInitialRun: true, print: line => output.push(line),
  });
  const bytes = fs.readFileSync(new URL(file, fixtures));
  engine.FS.writeFile('/sample', bytes);
  try { engine.callMain(['/sample', '--image-info']); }
  catch (error) { if (error.status !== 0) throw error; }
  const info = JSON.parse(output.join('\n'));
  assert.equal(info.arch, arch);
  assert.equal(info.ptrSize, 8);
  assert.ok(info.sections.length);
  assert.ok(info.regions.some(r => r.size));
  assert.ok(info.regions.every(r => r.off + r.size <= bytes.length));
  console.log(`${file} --image-info: passed`);
}
