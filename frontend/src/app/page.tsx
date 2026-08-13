"use client";

/**
 * The root path is a router, not a page.
 *
 * Where a visitor belongs depends on whether they have a session, which is only
 * knowable in the browser -- the token lives in `sessionStorage`, not a cookie
 * the server could read.
 */

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { Spinner } from "@/components/ui/states";
import { useAuth } from "@/lib/auth";

export default function RootPage() {
  const { user, initialising } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (initialising) return;
    router.replace(user ? "/dashboard" : "/login");
  }, [user, initialising, router]);

  return (
    <div className="flex min-h-screen items-center justify-center text-soc-muted">
      <Spinner className="h-6 w-6" />
    </div>
  );
}
