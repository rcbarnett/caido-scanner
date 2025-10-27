export const Severity = {
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

export type Finding = {
  name: string;
  description: string;
  severity: Severity;
  correlation: {
    requestID: string;
    locations: {
      start: number;
      end: number;
      hint?: string;
    }[];
  };
};

export type CheckOutput = unknown;

export type StepExecutionRecord = {
  stepName: string;
  stateBefore: Record<string, unknown>;
  stateAfter: Record<string, unknown>;
  findings: Finding[];
} & ({ result: "done" } | { result: "continue"; nextStep: string });

export enum ScanRunnableErrorCode {
  INTERRUPTED = "INTERRUPTED",
  REQUEST_NOT_FOUND = "REQUEST_NOT_FOUND",
  SCAN_ALREADY_RUNNING = "SCAN_ALREADY_RUNNING",
  RUNTIME_ERROR = "RUNTIME_ERROR",
  UNKNOWN_CHECK_ERROR = "UNKNOWN_CHECK_ERROR",
  REQUEST_FAILED = "REQUEST_FAILED",
}

export type CheckExecutionRecord = {
  checkId: string;
  targetRequestId: string;
  steps: StepExecutionRecord[];
} & (
  | {
      status: "completed";
      finalOutput: CheckOutput;
    }
  | {
      status: "failed";
      error: {
        code: ScanRunnableErrorCode;
        message: string;
      };
    }
);

export type ExecutionHistory = CheckExecutionRecord[];

export type ParsedTrace = {
  executionHistory: ExecutionHistory;
  totalChecks: number;
  totalSteps: number;
  totalFindings: number;
};

export type CurrentView =
  | { kind: "home" }
  | { kind: "checks"; executionHistory: ExecutionHistory }
  | { kind: "details"; check: CheckExecutionRecord };
