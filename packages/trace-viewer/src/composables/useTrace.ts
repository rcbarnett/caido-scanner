import { computed, ref } from "vue";

import { useViewState } from "./useViewState";

import type {
  CheckExecutionRecord,
  ExecutionHistory,
  ParsedTrace,
  StepExecutionRecord,
} from "@/types";

const executionHistory = ref<ExecutionHistory>([]);
const selectedCheckIndex = ref<number>(-1);
const selectedStepIndex = ref<number>(-1);

export const useTrace = () => {
  const viewState = useViewState();

  const loadTrace = (traceData: string) => {
    try {
      const decoded = atob(traceData);
      const parsed = JSON.parse(decoded) as ExecutionHistory;

      executionHistory.value = parsed;
      selectedCheckIndex.value = -1;
      selectedStepIndex.value = -1;
      viewState?.goToChecks(parsed);

      return { success: true, error: null };
    } catch (error) {
      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Failed to parse trace data",
      };
    }
  };

  const selectCheck = (index: number) => {
    selectedCheckIndex.value = index;
    selectedStepIndex.value = -1;
    const check = executionHistory.value[index];
    if (check) {
      viewState?.goToDetails(check);
    }
  };

  const selectStep = (index: number) => {
    selectedStepIndex.value = index;
  };

  const goBackToChecks = () => {
    viewState?.goToChecks(executionHistory.value);
    selectedCheckIndex.value = -1;
    selectedStepIndex.value = -1;
  };

  const clearTrace = () => {
    executionHistory.value = [];
    selectedCheckIndex.value = -1;
    selectedStepIndex.value = -1;
    viewState?.goHome();
  };

  const parsedTrace = computed((): ParsedTrace => {
    const totalChecks = executionHistory.value.length;
    const totalSteps = executionHistory.value.reduce(
      (sum, check) => sum + check.steps.length,
      0,
    );
    const totalFindings = executionHistory.value.reduce(
      (sum, check) =>
        sum +
        check.steps.reduce(
          (stepSum, step) => stepSum + step.findings.length,
          0,
        ),
      0,
    );

    return {
      executionHistory: executionHistory.value,
      totalChecks,
      totalSteps,
      totalFindings,
    };
  });

  const selectedCheck = computed((): CheckExecutionRecord | undefined => {
    if (
      selectedCheckIndex.value === -1 ||
      !executionHistory.value[selectedCheckIndex.value]
    ) {
      return undefined;
    }
    return executionHistory.value[selectedCheckIndex.value];
  });

  const selectedStep = computed((): StepExecutionRecord | undefined => {
    if (!selectedCheck.value || selectedStepIndex.value === -1) {
      return undefined;
    }
    return selectedCheck.value.steps[selectedStepIndex.value] || undefined;
  });

  const hasTrace = computed(() => executionHistory.value.length > 0);

  return {
    // State
    executionHistory,
    selectedCheckIndex,
    selectedStepIndex,

    // Computed
    parsedTrace,
    selectedCheck,
    selectedStep,
    hasTrace,

    // Actions
    loadTrace,
    selectCheck,
    selectStep,
    goBackToChecks,
    clearTrace,
  };
};
