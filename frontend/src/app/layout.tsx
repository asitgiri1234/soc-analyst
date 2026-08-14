import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { env } from "@/lib/env";

export const metadata: Metadata = {
  title: env.appName,
  description: "AI-assisted security operations center analyst platform.",
};

/*
 * `suppressHydrationWarning` on <html> and <body> only.
 *
 * Browser extensions — password managers, antivirus page scanners — attach
 * their own attributes to these two elements before React hydrates:
 * `bis_skin_checked`, `bis_register`, `data-cap-chrome-extension-installed`
 * and similar. The server never rendered them, so React reports a mismatch it
 * cannot do anything about, and a real mismatch would then be buried in that
 * noise.
 *
 * Deliberately not applied any deeper. The flag suppresses the warning for the
 * element it is on, and putting it on application markup would hide genuine
 * server/client divergence — which is the bug class this warning exists to
 * catch.
 */
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <body
        className="min-h-full bg-soc-base text-soc-text"
        suppressHydrationWarning
      >
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
