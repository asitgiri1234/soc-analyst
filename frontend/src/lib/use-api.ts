"use client";

/**
 * A hook for reading one API resource.
 *
 * Returns the four states a screen actually has to render -- loading, error,
 * empty, and data -- rather than leaving each page to invent its own booleans.
 * Emptiness is left to the caller to interpret, because "no rows" means
 * something different for an incident list than for a chart series.
 *
 * `reload` re-runs the request, which is what a screen needs after it has
 * changed something (a status update, a generated report).
 */

import { useCallback, useEffect, useState } from "react";

import { ApiError, apiFetch } from "@/lib/api-client";

export interface ApiResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Set when the failure was a 403, so a page can say so specifically. */
  forbidden: boolean;
  reload: () => void;
}

export function useApi<T>(path: string | null, deps: unknown[] = []): ApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [loading, setLoading] = useState(path !== null);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;

    // Everything that sets state lives in here rather than in the effect body,
    // so no state is written synchronously while the effect runs.
    async function load(): Promise<void> {
      if (path === null) {
        if (!cancelled) setLoading(false);
        return;
      }

      setLoading(true);
      setError(null);
      setForbidden(false);

      try {
        const result = await apiFetch<T>(path);
        if (!cancelled) setData(result);
      } catch (caught: unknown) {
        if (cancelled) return;
        const apiError = caught instanceof ApiError ? caught : null;
        setForbidden(apiError?.isForbidden ?? false);
        setError(apiError?.message ?? "Something went wrong.");
        setData(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
    // `path` and the caller's own dependencies drive the refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, nonce, ...deps]);

  return { data, error, loading, forbidden, reload };
}
