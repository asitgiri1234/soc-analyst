/**
 * An unknown route.
 *
 * Deliberately incurious: it does not report whether the path would have
 * existed for someone with a different role, because that would make the 404
 * page a way to map the console.
 */

import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="max-w-md text-center">
        <p className="font-mono text-sm text-soc-faint">404</p>
        <h1 className="mt-2 text-lg font-semibold text-soc-text">Page not found</h1>
        <p className="mt-2 text-sm text-soc-muted">
          That address does not match anything in the console.
        </p>
        <Link
          href="/dashboard"
          className="mt-6 inline-block rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400"
        >
          Back to overview
        </Link>
      </div>
    </main>
  );
}
