// Prove the web client's TypeScript opens what core wraps: every row of test-vectors/passkey_vault_core.json is
// opened with repos/web/src/lib/passkey-vault.ts (getVaultWrapKey + decryptVaultBlob). A row marked
// `"expect": "refuse"` (a changed byte, a wrong PRF output) must NOT open.
//
//   bun scripts/passkey-vectors/web-opens-core.ts <path to repos/web> [vectors.json]
//
// Prints `web-opens-core: N rows, P opened, R refused, 0 wrong` and exits 1 on any wrong row.
import { resolve } from 'node:path'

const webDir = process.argv[2]
if (!webDir) {
  console.error('usage: bun web-opens-core.ts <path to repos/web> [vectors.json]')
  process.exit(2)
}
const file = process.argv[3] ?? resolve(import.meta.dir, '../../test-vectors/passkey_vault_core.json')
const vault = await import(resolve(webDir, 'src/lib/passkey-vault.ts'))
const data = await Bun.file(file).json()

const unhex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)))
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

let opened = 0
let refused = 0
let wrong = 0
for (const [i, row] of data.rows.entries()) {
  const wrapKey: Uint8Array = await vault.getVaultWrapKey(`cred-${i}`, unhex(row.prf_output), false)
  const out: Uint8Array | null = await vault.decryptVaultBlob(wrapKey, unhex(row.blob))
  if (row.expect === 'refuse') {
    if (out === null) refused++
    else {
      wrong++
      console.error(`row ${i}: web opened a row it must refuse`)
    }
  } else if (out !== null && hex(out) === row.master_key) {
    opened++
  } else {
    wrong++
    console.error(`row ${i}: web did not open core's blob`)
  }
}
console.log(`web-opens-core: ${data.rows.length} rows, ${opened} opened, ${refused} refused, ${wrong} wrong`)
process.exit(wrong === 0 && data.rows.length > 0 ? 0 : 1)
