// Compiled, never run: run.sh type-checks this against the generated .d.ts of both targets. It pins what a
// TypeScript consumer sees of `WasmDownloadPlanner.poll()`; each `@ts-expect-error` fails the check if the line
// beneath it stops being an error (for instance if the link of a fetch step became a plain string again).
import {
  WasmDirectHealth,
  WasmDownloadPlanner,
  WasmSignedUrl,
  resumeTransport,
  storageGetTotalMs,
  storagePutTotalMs,
  type DirectPoll,
  type DirectVerdict,
} from "./PKG/beebeeb_wasm"

declare const planner: WasmDownloadPlanner

// No annotation: the type comes from the declaration of poll() itself (a poll() typed `any` would not fail below).
const step = planner.poll(0)

if (step.kind === "fetch") {
  const link: string = step.url.raw()
  const object: WasmSignedUrl = step.url
  const safeToLog: string = step.url.redacted()
  // @ts-expect-error the link of a fetch step is a WasmSignedUrl, not a string
  const notAString: string = step.url
  void [link, object, safeToLog, notAString]
} else {
  // @ts-expect-error only a fetch step carries a link
  void step.url
}

// The fields that are `null` when absent are typed so (the planner serialises absent values as null, never undefined).
if (step.kind === "wait") {
  // @ts-expect-error until_ms is null while the planner waits for a request that is outstanding
  const until: number = step.until_ms
  void until
}
if (step.kind === "request_window") {
  // @ts-expect-error object_version_id is null for the first, unpinned request
  const version: string = step.request.object_version_id
  void version
}
if (step.kind === "stop" && step.verdict.kind === "terminal") {
  // @ts-expect-error a terminal answer may carry no error code
  const code: string = step.verdict.error
  void code
}

// Every kind is handled, and a new one would not compile here.
export const first: string = describe(step)

export function describe(p: DirectPoll): string {
  switch (p.kind) {
    case "request_window":
      return `POST window from ${p.request.start_index}, ${p.request.count} chunks, renewal ${p.request.renewal}`
    case "fetch":
      return `GET chunk ${p.index} (${p.length} bytes) from ${p.url}`
    case "fetch_via_api":
      return `GET chunk ${p.index} of ${p.object_version_id} through the API`
    case "wait":
      return p.until_ms === null ? "wait for the outstanding request" : `wait until ${p.until_ms}`
    case "done":
      return "done"
    case "stop":
      return verdict(p.verdict)
    default: {
      const unhandled: never = p
      return unhandled
    }
  }
}

function verdict(v: DirectVerdict): string {
  switch (v.kind) {
    case "api_for_file":
    case "restart":
    case "corrupt":
      return v.kind
    case "terminal":
      return `terminal ${v.status} ${v.error ?? ""}`
  }
}

// The download-side additions (clients plan A1, A2): what a TypeScript consumer sees.
declare const health: WasmDirectHealth
const may: boolean = health.mayStart("download", 0)
const mayFile: boolean = health.mayStartFile("upload", 0, false)
// An absent timestamp is `undefined` (wasm-bindgen's `Option<f64>`), a present one a number.
const lastGaveUp: number | undefined = health.lastGaveUpMs("download")
// @ts-expect-error a missing timestamp is not a number
const lastIsANumber: number = health.lastGaveUpMs("download")
health.gaveUp("upload", Date.now())
health.restore("download", 1)
const action: string = resumeTransport("direct", { kind: "unknown" }, false)
const putMs: number = storagePutTotalMs(4194332)
const getMs: number = storageGetTotalMs(0)
planner.setMaxInFlightBytes(64 * 1024 * 1024)
const gaveUpStorage: boolean = planner.storageGivenUp()
void [may, mayFile, lastGaveUp, lastIsANumber, action, putMs, getMs, gaveUpStorage]
