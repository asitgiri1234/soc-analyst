import { BackendStatus } from "@/components/backend-status";
import { env } from "@/lib/env";

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center gap-8 px-6 py-16">
      <header className="space-y-2">
        <p className="text-xs font-medium uppercase tracking-widest text-black/50 dark:text-white/50">
          Phase 0 — Foundation
        </p>
        <h1 className="text-3xl font-semibold tracking-tight">{env.appName}</h1>
        <p className="text-black/70 dark:text-white/70">
          The monorepo scaffolding is in place. Feature work lands in later phases.
        </p>
      </header>

      <BackendStatus />

      <section className="space-y-3 text-sm">
        <h2 className="font-medium">Local endpoints</h2>
        <ul className="space-y-1 text-black/70 dark:text-white/70">
          <li>
            API docs — <code>{env.apiBaseUrl}/docs</code>
          </li>
          <li>
            Liveness — <code>{`${env.apiBaseUrl}/api/${env.apiVersion}/health`}</code>
          </li>
          <li>
            Readiness — <code>{`${env.apiBaseUrl}/api/${env.apiVersion}/ready`}</code>
          </li>
        </ul>
      </section>
    </main>
  );
}
