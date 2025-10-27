<script setup lang="ts">
import Card from "primevue/card";
import Tag from "primevue/tag";

import { useTrace } from "@/composables/useTrace";

const { selectedStep } = useTrace();

const formatJSON = (obj: unknown): string => {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "critical":
      return "danger";
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "info";
    case "info":
      return "info";
    default:
      return "info";
  }
};
</script>

<template>
  <div class="h-full flex flex-col">
    <Card class="h-full" :pt="{ content: 'h-full flex flex-col' }">
      <template #title>
        <div>
          <h2 class="text-lg font-semibold text-surface-0">State Details</h2>
          <p v-if="selectedStep" class="text-sm text-surface-300">
            Step: {{ selectedStep.stepName }}
          </p>
        </div>
      </template>

      <template #content>
        <div
          v-if="!selectedStep"
          class="flex-1 flex items-center justify-center"
        >
          <p class="text-surface-400">Select a step to view state details</p>
        </div>

        <div v-else class="flex-1 overflow-y-auto">
          <div class="space-y-6">
            <!-- Findings Section -->
            <div v-if="selectedStep.findings.length > 0">
              <h3 class="text-md font-semibold text-surface-0 mb-3">
                Findings ({{ selectedStep.findings.length }})
              </h3>
              <div class="space-y-3">
                <Card
                  v-for="(finding, index) in selectedStep.findings"
                  :key="index"
                  class="border"
                  :class="{
                    'border-red-500 bg-red-900/20':
                      finding.severity === 'critical' ||
                      finding.severity === 'high',
                    'border-yellow-500 bg-yellow-900/20':
                      finding.severity === 'medium',
                    'border-blue-500 bg-blue-900/20':
                      finding.severity === 'low' || finding.severity === 'info',
                  }"
                >
                  <template #content>
                    <div class="flex items-center justify-between mb-2">
                      <h4 class="font-medium text-sm text-surface-0">
                        {{ finding.name }}
                      </h4>
                      <Tag
                        :value="finding.severity"
                        :severity="getSeverityColor(finding.severity)"
                      />
                    </div>
                    <p class="text-sm text-surface-200 mb-2">
                      {{ finding.description }}
                    </p>
                    <div class="text-xs text-surface-400">
                      Request: {{ finding.correlation.requestID }}
                      <span v-if="finding.correlation.locations.length > 0">
                        • {{ finding.correlation.locations.length }} location(s)
                      </span>
                    </div>
                  </template>
                </Card>
              </div>
            </div>

            <!-- State Before/After Section -->
            <div>
              <h3 class="text-md font-semibold text-surface-0 mb-3">
                State Transition
              </h3>
              <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <!-- State Before -->
                <Card>
                  <template #title>
                    <h4 class="text-sm font-medium text-surface-0">
                      State Before
                    </h4>
                  </template>
                  <template #content>
                    <div class="bg-surface-800 rounded p-3">
                      <pre
                        class="text-xs text-surface-200 whitespace-pre-wrap overflow-x-auto"
                        >{{ formatJSON(selectedStep.stateBefore) }}</pre
                      >
                    </div>
                  </template>
                </Card>

                <!-- State After -->
                <Card>
                  <template #title>
                    <h4 class="text-sm font-medium text-surface-0">
                      State After
                    </h4>
                  </template>
                  <template #content>
                    <div class="bg-surface-800 rounded p-3">
                      <pre
                        class="text-xs text-surface-200 whitespace-pre-wrap overflow-x-auto"
                        >{{ formatJSON(selectedStep.stateAfter) }}</pre
                      >
                    </div>
                  </template>
                </Card>
              </div>
            </div>

            <!-- Step Result -->
            <div>
              <h3 class="text-md font-semibold text-surface-0 mb-3">
                Step Result
              </h3>
              <Card>
                <template #content>
                  <div class="flex items-center justify-between">
                    <span class="text-sm font-medium text-surface-200">
                      Result:
                    </span>
                    <Tag
                      :value="selectedStep.result"
                      :severity="
                        selectedStep.result === 'done' ? 'success' : 'warning'
                      "
                    />
                  </div>
                  <div v-if="selectedStep.result === 'continue'" class="mt-2">
                    <span class="text-sm text-surface-300">Next step: </span>
                    <span class="text-sm font-medium text-surface-0">
                      {{ selectedStep.nextStep }}
                    </span>
                  </div>
                </template>
              </Card>
            </div>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
