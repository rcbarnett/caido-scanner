import { ref, computed } from 'vue'
import type { ExecutionHistory, CheckExecutionRecord, StepExecutionRecord, ParsedTrace } from '@/types'

const executionHistory = ref<ExecutionHistory>([])
const selectedCheckIndex = ref<number>(-1)
const selectedStepIndex = ref<number>(-1)
const currentView = ref<'checks' | 'details'>('checks')

export const useTrace = () => {
  const loadTrace = (traceData: string) => {
    try {
      const decoded = atob(traceData)
      const parsed = JSON.parse(decoded) as ExecutionHistory
      
      executionHistory.value = parsed
      selectedCheckIndex.value = -1
      selectedStepIndex.value = -1
      currentView.value = 'checks'
      
      return { success: true, error: null }
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Failed to parse trace data' 
      }
    }
  }

  const selectCheck = (index: number) => {
    selectedCheckIndex.value = index
    selectedStepIndex.value = -1
    currentView.value = 'details'
  }

  const selectStep = (index: number) => {
    selectedStepIndex.value = index
  }

  const goBackToChecks = () => {
    currentView.value = 'checks'
    selectedCheckIndex.value = -1
    selectedStepIndex.value = -1
  }

  const clearTrace = () => {
    executionHistory.value = []
    selectedCheckIndex.value = -1
    selectedStepIndex.value = -1
    currentView.value = 'checks'
  }

  const parsedTrace = computed((): ParsedTrace => {
    const totalChecks = executionHistory.value.length
    const totalSteps = executionHistory.value.reduce((sum, check) => sum + check.steps.length, 0)
    const totalFindings = executionHistory.value.reduce(
      (sum, check) => sum + check.steps.reduce((stepSum, step) => stepSum + step.findings.length, 0),
      0
    )

    return {
      executionHistory: executionHistory.value,
      totalChecks,
      totalSteps,
      totalFindings
    }
  })

  const selectedCheck = computed((): CheckExecutionRecord | null => {
    if (selectedCheckIndex.value === -1 || !executionHistory.value[selectedCheckIndex.value]) {
      return null
    }
    return executionHistory.value[selectedCheckIndex.value]
  })

  const selectedStep = computed((): StepExecutionRecord | null => {
    if (!selectedCheck.value || selectedStepIndex.value === -1) {
      return null
    }
    return selectedCheck.value.steps[selectedStepIndex.value] || null
  })

  const hasTrace = computed(() => executionHistory.value.length > 0)

  return {
    // State
    executionHistory,
    selectedCheckIndex,
    selectedStepIndex,
    currentView,
    
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
    clearTrace
  }
}
