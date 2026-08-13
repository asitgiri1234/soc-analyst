/**
 * Fetch wrapper around the backend API.
 *
 * Three jobs beyond calling `fetch`:
 *
 * *Attach the token.* The access token lives in one place (`token-store`) and
 * is read at call time, so a login or logout takes effect on the next request
 * without every caller re-subscribing.
 *
 * *Normalise errors.* FastAPI returns `detail` as a string for `HTTPException`
 * and as a list of objects for validation failures. Callers should not each
 * have to know that, so both collapse to one readable message here.
 *
 * *Report expiry once.* A 401 means the token is gone or revoked; the store is
 * notified so the session ends rather than every screen showing its own error.
 */

import { apiUrl } from "@/lib/env";
import { clearToken, getToken } from "@/lib/token-store";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** True when the caller is authenticated but not permitted. */
  get isForbidden(): boolean {
    return this.status === 403;
  }
}

interface ValidationDetail {
  loc?: (string | number)[];
  msg?: string;
}

/** Turn a FastAPI error body into a single sentence. */
function readDetail(body: unknown, fallback: string): string {
  if (typeof body !== "object" || body === null) return fallback;
  const detail = (body as { detail?: unknown }).detail;

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const parts = (detail as ValidationDetail[])
      .map((item) => {
        // `loc` starts with "body" or "query"; the field name is what helps.
        const field = item.loc?.slice(1).join(".");
        return field ? `${field}: ${item.msg ?? "invalid"}` : item.msg;
      })
      .filter(Boolean);
    if (parts.length > 0) return parts.join("; ");
  }

  return fallback;
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  /** Set false for the login call, which has no token to send yet. */
  authenticated?: boolean;
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, authenticated = true, headers, ...rest } = options;

  const requestHeaders = new Headers(headers);
  if (body !== undefined) requestHeaders.set("Content-Type", "application/json");

  if (authenticated) {
    const token = getToken();
    if (token) requestHeaders.set("Authorization", `Bearer ${token}`);
  }

  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      ...rest,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    // A network-level failure has no status; 0 distinguishes it from any
    // answer the server actually gave.
    throw new ApiError("Cannot reach the backend API.", 0);
  }

  if (response.status === 204) return undefined as T;

  const payload: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401 && authenticated) clearToken();
    throw new ApiError(
      readDetail(payload, `Request failed with status ${response.status}`),
      response.status,
    );
  }

  return payload as T;
}

/** Build a query string, dropping keys the caller left undefined. */
export function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}
