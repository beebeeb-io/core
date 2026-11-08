// Generate test-vectors/passkey_vault.json FROM the web client's own TypeScript (repos/web/src/lib/passkey-vault.ts),
// so core is held to what web actually does, not to core's reading of it.
//
//   bun scripts/passkey-vectors/from-web.ts <path to repos/web> > test-vectors/passkey_vault.json
//
// Each row: a PRF output and a vault key (fixed, derived from the row index), the wrap key web derives from that PRF
// output, and the escrow blob web's encryptVaultBlob produces (its nonce is random; core re-wraps with the blob's own
// nonce and must produce the same bytes). Also the PRF eval input web passes, and the hmac-secret salt a browser
// derives from it per WebAuthn L3 section 10.1.4 (SHA-256("WebAuthn PRF" || 0x00 || input)), computed here with
// WebCrypto, independently of core.
import { resolve } from 'node:path'

const webDir = process.argv[2]
if (!webDir) {
  console.error('usage: bun from-web.ts <path to repos/web>')
  process.exit(2)
}
const vault = await import(resolve(webDir, 'src/lib/passkey-vault.ts'))

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const buf = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    buf.set(p, at)
    at += p.length
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf))
}
const fixed = (label: string, i: number) => sha256([new TextEncoder().encode(`passkey-vault-vector/${label}/${i}`)])

const prfInput = new Uint8Array(vault.prfExtensionInputs().prf.eval.first as Uint8Array)
const hmacSalt = await sha256([new TextEncoder().encode('WebAuthn PRF'), new Uint8Array([0]), prfInput])

const rows = []
for (let i = 0; i < 6; i++) {
  const prf = await fixed('prf', i)
  const master = await fixed('master', i)
  const wrapKey: Uint8Array = await vault.getVaultWrapKey(`cred-${i}`, prf, false)
  const blob: Uint8Array = await vault.encryptVaultBlob(wrapKey, master)
  const opened: Uint8Array | null = await vault.decryptVaultBlob(wrapKey, blob)
  if (!opened || hex(opened) !== hex(master)) throw new Error(`web did not open its own row ${i}`)
  rows.push({ prf_output: hex(prf), master_key: hex(master), wrap_key: hex(wrapKey), blob: hex(blob) })
}

console.log(
  JSON.stringify(
    {
      source: 'repos/web/src/lib/passkey-vault.ts via scripts/passkey-vectors/from-web.ts',
      prf_eval_input: hex(prfInput),
      hmac_secret_salt: hex(hmacSalt),
      rows,
    },
    null,
    2,
  ),
)
