// `env` from cloudflare:test is typed as Cloudflare.Env, which ships as an
// empty interface for a project to extend. The Worker declares its own Env, so
// this points one at the other rather than keeping a second list of bindings
// that can drift from the first.
import type { Env as WorkerEnv } from "../src/worker";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {}
  }
}
