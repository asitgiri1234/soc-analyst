/**
 * Layout for every authenticated screen.
 *
 * A route group rather than a path segment, so the guard applies to
 * `/dashboard`, `/incidents` and the rest without pushing `/console` into every
 * URL an analyst has to share.
 */

import type { ReactNode } from "react";

import { AppShell } from "@/components/layout/app-shell";

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
