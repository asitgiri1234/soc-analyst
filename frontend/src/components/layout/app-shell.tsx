"use client";

/**
 * The authenticated shell: route guard, navigation, and the session badge.
 *
 * The guard here is a convenience, not a security boundary. It stops an
 * unauthenticated browser rendering an empty console, but every screen inside
 * gets its data from the API, and the API authorises each request on its own.
 * Nothing sensitive exists in this bundle to be revealed by defeating it.
 */

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { Spinner } from "@/components/ui/states";
import { useAuth } from "@/lib/auth";
import { env } from "@/lib/env";
import { ROLE_LABEL } from "@/lib/rbac";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: "▦" },
  { href: "/incidents", label: "Incidents", icon: "⚠" },
  { href: "/anomalies", label: "Anomalies", icon: "◈" },
  { href: "/log-sources", label: "Log sources", icon: "⛁" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const { user, initialising, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!initialising && !user) {
      // Preserve where they were headed, so login returns them to it.
      const next = encodeURIComponent(pathname);
      router.replace(`/login?next=${next}`);
    }
  }, [user, initialising, pathname, router]);

  if (initialising) {
    return (
      <div className="flex min-h-screen items-center justify-center text-soc-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (!user) {
    // The redirect above is in flight; render nothing rather than a flash of
    // console chrome.
    return <div className="min-h-screen" />;
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-soc-border bg-soc-surface md:flex">
        <div className="flex items-center gap-2 border-b border-soc-border px-5 py-4">
          <span className="text-lg" aria-hidden>
            🛡️
          </span>
          <span className="text-sm font-semibold tracking-tight">{env.appName}</span>
        </div>

        <nav className="flex-1 space-y-1 p-3" aria-label="Main">
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                  active
                    ? "bg-sky-500/10 text-sky-300"
                    : "text-soc-muted hover:bg-soc-hover hover:text-soc-text"
                }`}
              >
                <span aria-hidden className="w-4 text-center">
                  {item.icon}
                </span>
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-soc-border p-3">
          <div className="rounded-lg bg-soc-raised px-3 py-2">
            <p className="truncate text-sm font-medium text-soc-text">{user.username}</p>
            <p className="text-xs text-soc-muted">{ROLE_LABEL[user.role]}</p>
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            className="mt-2 w-full rounded-lg px-3 py-2 text-left text-sm text-soc-muted transition-colors hover:bg-soc-hover hover:text-soc-text"
          >
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile bar: the sidebar collapses, the nav does not disappear. */}
        <header className="flex items-center justify-between gap-3 border-b border-soc-border bg-soc-surface px-4 py-3 md:hidden">
          <span className="text-sm font-semibold">{env.appName}</span>
          <button
            type="button"
            onClick={() => void logout()}
            className="text-sm text-soc-muted"
          >
            Sign out
          </button>
        </header>
        <nav
          className="flex gap-1 overflow-x-auto border-b border-soc-border bg-soc-surface px-2 py-2 md:hidden"
          aria-label="Main"
        >
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`rounded-lg px-3 py-1.5 text-sm whitespace-nowrap ${
                  active ? "bg-sky-500/10 text-sky-300" : "text-soc-muted"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <main className="min-w-0 flex-1 px-4 py-6 md:px-8 md:py-8">{children}</main>
      </div>
    </div>
  );
}

/** A page heading with optional actions on the right. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-soc-text">{title}</h1>
        {description && <p className="mt-1 text-sm text-soc-muted">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
