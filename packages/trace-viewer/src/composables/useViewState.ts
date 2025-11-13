import { createInjectionState } from "@vueuse/core";
import { ref } from "vue";

import type {
  CheckExecutionRecord,
  CurrentView,
  ExecutionHistory,
} from "@/types";

const [useProvideViewState, useViewState] = createInjectionState(() => {
  const currentView = ref<CurrentView>({ kind: "home" });

  const setView = (view: CurrentView) => {
    currentView.value = view;
  };

  const goHome = () => {
    currentView.value = { kind: "home" };
  };

  const goToChecks = (executionHistory: ExecutionHistory) => {
    currentView.value = { kind: "checks", executionHistory };
  };

  const goToDetails = (check: CheckExecutionRecord) => {
    currentView.value = { kind: "details", check };
  };

  return {
    currentView,
    setView,
    goHome,
    goToChecks,
    goToDetails,
  };
});

export { useProvideViewState, useViewState };
