/**
 * The role hierarchy, mirrored from `app.core.authz`.
 *
 * This decides what the UI *offers*, never what is *allowed*. The server
 * enforces the same ranking on every request, so a user who reaches a hidden
 * action by other means still gets a 403. Hiding a control the caller cannot
 * use is a courtesy, not a control.
 */

import type { UserRole } from "@/types/api";

const RANK: Record<UserRole, number> = {
  viewer: 0,
  analyst: 10,
  admin: 20,
};

export function hasAtLeast(role: UserRole | undefined, minimum: UserRole): boolean {
  if (!role) return false;
  return RANK[role] >= RANK[minimum];
}

/**
 * Create and modify incidents, notes, and detections.
 *
 * Reading needs no helper: every authenticated tier may read, so a screen the
 * user can reach at all is one they may read.
 */
export const canInvestigate = (role: UserRole | undefined) => hasAtLeast(role, "analyst");

/** Generate an AI report -- analyst or above, matching the analyze endpoint. */
export const canGenerateReport = (role: UserRole | undefined) =>
  hasAtLeast(role, "analyst");

/**
 * Delete an incident. Admin only, matching the endpoint.
 *
 * Deletion is the one incident operation reserved for ADMIN: it destroys an
 * investigation record along with its notes and report history, which is not
 * something a shift analyst should be able to do by accident.
 */
export const canDeleteIncident = (role: UserRole | undefined) =>
  hasAtLeast(role, "admin");

export const ROLE_LABEL: Record<UserRole, string> = {
  admin: "Administrator",
  analyst: "Analyst",
  viewer: "Viewer",
};
