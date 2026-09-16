/**
 * Loads the vendored UMD bundle into globalThis so the browser modules can be
 * imported under Node exactly as the page imports them. The point is to test the
 * artifact that actually ships, not a separately installed copy of xrpl.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import path from 'node:path';

const require = createRequire(import.meta.url);
const bundlePath = path.join(import.meta.dirname, '..', 'vendor', 'xrpl-5.2.0.min.js');
const source = readFileSync(bundlePath, 'utf8');

// UMD checks for module/exports/define. Hide all three so it takes the global branch.
const sandbox = {
  globalThis: undefined,
  window: undefined,
  self: undefined,
  console,
  crypto: globalThis.crypto,
  TextEncoder,
  TextDecoder,
  URL,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  process,
  Buffer,
  require,
  // webpack's runtime resolves publicPath from the document; the bundle never uses
  // it (no lazy chunks) but it refuses to initialise without one.
  document: {
    baseURI: 'file:///vendor/',
    currentScript: { src: 'file:///vendor/xrpl-5.2.0.min.js', tagName: 'SCRIPT' },
    getElementsByTagName: () => [],
    createElement: () => ({ setAttribute() {}, style: {} }),
    head: { appendChild() {} },
  },
  location: { href: 'file:///vendor/', protocol: 'file:' },
  navigator: { userAgent: 'node' },
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;

vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'xrpl-5.2.0.min.js' });

if (!sandbox.xrpl) throw new Error('vendored bundle did not expose a global `xrpl`');

globalThis.xrpl = sandbox.xrpl;
export const xrpl = sandbox.xrpl;
export const VENDOR_PATH = bundlePath;
