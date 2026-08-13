/**
 * Loading, error and empty states.
 *
 * Shared components rather than per-page improvisation, because these are the
 * states an operator actually spends time in when something is wrong. An error
 * that offers no way forward is a dead end, so `ErrorState` always carries a
 * retry, and a 403 says plainly that it is a permission boundary rather than a
 * fault the operator can retry their way out of.
 */

import type { ReactNode } from "react";

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v3a5 5 0 0 0-5 5H4z"
      />
    </svg>
  );
}

/** Skeleton rows, sized to the table they stand in for. */
export function LoadingState({ rows = 4, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div className="space-y-3 px-5 py-6" role="status" aria-live="polite">
      <span className="sr-only">{label}…</span>
      {Array.from({ length: rows }).map((_, index) => (
        <div
          key={index}
          className="soc-pulse h-9 rounded-lg bg-soc-raised"
          style={{ animationDelay: `${index * 120}ms` }}
          aria-hidden
        />
      ))}
    </div>
  );
}

export function ErrorState({
  message,
  forbidden = false,
  onRetry,
}: {
  message: string;
  forbidden?: boolean;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center gap-3 px-5 py-10 text-center">
      <div
        className={`flex h-10 w-10 items-center justify-center rounded-full ${
          forbidden ? "bg-amber-500/15 text-amber-400" : "bg-rose-500/15 text-rose-400"
        }`}
        aria-hidden
      >
        {forbidden ? "🔒" : "!"}
      </div>
      <div>
        <p className="text-sm font-medium text-soc-text">
          {forbidden ? "Not permitted" : "Could not load this"}
        </p>
        <p className="mt-1 max-w-md text-sm text-soc-muted">{message}</p>
      </div>
      {onRetry && !forbidden && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded-lg border border-soc-border px-3 py-1.5 text-sm text-soc-text transition-colors hover:bg-soc-hover"
        >
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 px-5 py-10 text-center">
      <p className="text-sm font-medium text-soc-text">{title}</p>
      {description && <p className="max-w-md text-sm text-soc-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
