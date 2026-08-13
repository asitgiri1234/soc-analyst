"use client";

/**
 * The last line of defence for a render that threw.
 *
 * Next replaces the page with this rather than showing a blank screen. It says
 * what can be done next and nothing about what went wrong internally: React
 * already strips the message from production builds, and repeating a stack
 * trace to an operator who cannot act on it helps nobody.
 *
 * The digest is Next's own identifier for the error, which the server log
 * carries too. It is the frontend's equivalent of the API's request id.
 */

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Recorded in the browser console for whoever is debugging; nothing is
    // sent anywhere, since there is no telemetry sink in this deployment.
    if (process.env.NODE_ENV !== "production") {
      console.error("Unhandled UI error:", error);
    }
  }, [error]);

  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="max-w-md text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-500/10 text-xl">
          ⚠
        </div>
        <h1 className="text-lg font-semibold text-soc-text">Something went wrong</h1>
        <p className="mt-2 text-sm text-soc-muted">
          This screen could not be displayed. The rest of the console is still
          available.
        </p>
        {error.digest && (
          <p className="mt-3 font-mono text-xs text-soc-faint">
            Reference: {error.digest}
          </p>
        )}
        <div className="mt-6 flex justify-center gap-3">
          <button
            type="button"
            onClick={reset}
            className="rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400"
          >
            Try again
          </button>
          <a
            href="/dashboard"
            className="rounded-lg border border-soc-border px-4 py-2 text-sm text-soc-text transition-colors hover:bg-soc-hover"
          >
            Back to overview
          </a>
        </div>
      </div>
    </main>
  );
}
