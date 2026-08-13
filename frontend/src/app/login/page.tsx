"use client";

/**
 * Sign in.
 *
 * The error message is whatever the server said, and the server deliberately
 * says "incorrect email or password" without revealing which half was wrong --
 * the form must not improve on that, or it becomes an account enumeration
 * oracle. So there is no client-side "no such user" check.
 */

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent } from "react";

import { Spinner } from "@/components/ui/states";
import { ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";
import { env } from "@/lib/env";

function LoginForm() {
  const { login, user, initialising } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Only ever a path within this app: an absolute URL here would turn the
  // login redirect into an open redirect.
  const rawNext = searchParams.get("next");
  const next = rawNext && rawNext.startsWith("/") && !rawNext.startsWith("//")
    ? rawNext
    : "/dashboard";

  useEffect(() => {
    if (!initialising && user) router.replace(next);
  }, [user, initialising, next, router]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(email, password);
      router.replace(next);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "Sign in failed. Please try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="soc-grid-bg flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-soc-border bg-soc-surface text-xl">
            🛡️
          </div>
          <h1 className="text-xl font-semibold tracking-tight">{env.appName}</h1>
          <p className="mt-1 text-sm text-soc-muted">
            Security operations console
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="space-y-4 rounded-xl border border-soc-border bg-soc-surface p-6"
          noValidate
        >
          <div className="space-y-1.5">
            <label htmlFor="email" className="block text-sm font-medium text-soc-text">
              Email
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-text placeholder:text-soc-faint focus:border-soc-accent focus:outline-none"
              placeholder="analyst@example.com"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="password" className="block text-sm font-medium text-soc-text">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-text placeholder:text-soc-faint focus:border-soc-accent focus:outline-none"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting && <Spinner />}
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-soc-faint">
          Access is logged. Unauthorised use is prohibited.
        </p>
      </div>
    </main>
  );
}

export default function LoginPage() {
  // `useSearchParams` requires a Suspense boundary under static rendering.
  return (
    <Suspense fallback={<div className="min-h-screen" />}>
      <LoginForm />
    </Suspense>
  );
}
