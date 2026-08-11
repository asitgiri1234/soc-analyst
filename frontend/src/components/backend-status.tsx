"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "@/lib/api-client";
import type { HealthResponse } from "@/types/health";

type State =
  | { kind: "loading" }
  | { kind: "online"; health: HealthResponse }
  | { kind: "offline" };

/** Polls the backend liveness endpoint once on mount. */
export function BackendStatus() {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;

    apiFetch<HealthResponse>("/health")
      .then((health) => {
        if (!cancelled) setState({ kind: "online", health });
      })
      .catch(() => {
        if (!cancelled) setState({ kind: "offline" });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const dotClass =
    state.kind === "online"
      ? "bg-emerald-500"
      : state.kind === "offline"
        ? "bg-red-500"
        : "bg-zinc-400";

  return (
    <div className="flex items-center gap-3 rounded-lg border border-black/10 px-4 py-3 dark:border-white/15">
      <span className={`h-2.5 w-2.5 rounded-full ${dotClass}`} aria-hidden />
      <div className="text-sm">
        <p className="font-medium">Backend API</p>
        <p className="text-black/60 dark:text-white/60">
          {state.kind === "loading" && "Checking…"}
          {state.kind === "offline" && "Unreachable — is the backend running on port 8000?"}
          {state.kind === "online" &&
            `${state.health.service} v${state.health.version} (${state.health.environment})`}
        </p>
      </div>
    </div>
  );
}
