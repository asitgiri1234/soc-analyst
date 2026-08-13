"use client";

/**
 * Authentication state for the whole app.
 *
 * The provider owns the current user; the token itself lives in `token-store`
 * so non-React code (the fetch wrapper) can read it without a hook. The two are
 * kept in step by subscribing to the store: when a 401 clears the token
 * mid-request, the user is dropped here too and the app returns to the login
 * screen instead of rendering a shell with no session behind it.
 */

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { ApiError, apiFetch } from "@/lib/api-client";
import { clearToken, getToken, setToken, subscribe } from "@/lib/token-store";
import type { TokenResponse, User } from "@/types/api";

interface AuthState {
  user: User | null;
  /** True until the stored session has been checked on first load. */
  initialising: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [initialising, setInitialising] = useState(true);
  const router = useRouter();

  // On mount, a token in sessionStorage is a claim, not proof. Ask the server
  // who it belongs to: it may have been revoked by a logout in another tab.
  useEffect(() => {
    let cancelled = false;

    // The whole check runs inside this function rather than in the effect
    // body, so state is never set synchronously during the effect.
    async function restore(): Promise<void> {
      if (!getToken()) {
        if (!cancelled) setInitialising(false);
        return;
      }
      try {
        const me = await apiFetch<User>("/auth/me");
        if (!cancelled) setUser(me);
      } catch {
        if (!cancelled) {
          clearToken();
          setUser(null);
        }
      } finally {
        if (!cancelled) setInitialising(false);
      }
    }

    void restore();

    return () => {
      cancelled = true;
    };
  }, []);

  // The fetch wrapper clears the token on any 401. Follow it here.
  useEffect(
    () =>
      subscribe(() => {
        if (!getToken()) setUser(null);
      }),
    [],
  );

  const login = useCallback(async (email: string, password: string) => {
    const response = await apiFetch<TokenResponse>("/auth/login", {
      method: "POST",
      body: { email, password },
      authenticated: false,
    });
    setToken(response.access_token, response.expires_in);
    setUser(response.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      // Revokes the token server-side; a failure here must not strand the user
      // in a session they have asked to end.
      await apiFetch<unknown>("/auth/logout", { method: "POST" });
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
    } finally {
      clearToken();
      setUser(null);
      router.replace("/login");
    }
  }, [router]);

  const value = useMemo<AuthState>(
    () => ({ user, initialising, login, logout }),
    [user, initialising, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside an AuthProvider");
  return context;
}
