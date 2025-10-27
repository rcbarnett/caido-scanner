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

export type JSONSerializable = 
  | string 
  | number 
  | boolean 
  | null 
  | JSONSerializable[] 
  | { [key: string]: JSONSerializable };

export type CheckOutput = JSONSerializable | undefined;

export type StepExecutionRecord = {
  stepName: string;
  stateBefore: JSONSerializable;
  stateAfter: JSONSerializable;
  findings: Finding[];
} & ({ result: "done" } | { result: "continue"; nextStep: string });

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
        code: string;
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
