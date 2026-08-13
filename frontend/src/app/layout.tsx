import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { env } from "@/lib/env";

export const metadata: Metadata = {
  title: env.appName,
  description: "AI-assisted security operations center analyst platform.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full bg-soc-base text-soc-text">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
