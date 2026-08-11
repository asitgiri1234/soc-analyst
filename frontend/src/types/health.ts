export interface HealthResponse {
  status: "ok";
  service: string;
  environment: string;
  version: string;
}

export interface DependencyStatus {
  connected: boolean;
  detail: string | null;
}

export interface ReadinessResponse {
  status: "ready" | "degraded";
  postgres: DependencyStatus;
  redis: DependencyStatus;
}
