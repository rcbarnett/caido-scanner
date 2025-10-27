<script setup lang="ts">
import Tag from "primevue/tag";

import { useTrace } from "@/composables/useTrace";

const { selectedCheck, selectedStepIndex, selectStep } = useTrace();
</script>

<template>
  <div class="flex flex-col gap-2 bg-surface-800 rounded p-4">
    <h2 class="text-lg font-semibold text-surface-0">Steps</h2>
    <p v-if="selectedCheck" class="text-sm text-surface-300">
      {{ selectedCheck.steps.length }} steps for
      {{ selectedCheck.checkId }}
    </p>

    <div v-if="!selectedCheck" class="flex-1 flex items-center justify-center">
      <p class="text-surface-400">Select a check to view steps</p>
    </div>

    <div v-else class="flex-1 overflow-y-auto">
      <div class="space-y-2">
        <div
          v-for="(step, index) in selectedCheck.steps"
          :key="`${step.stepName}-${index}`"
          class="p-3 rounded-lg cursor-pointer transition-colors border"
          :class="{
            'bg-secondary-400/20 border-secondary-400':
              selectedStepIndex === index,
            'bg-surface-700 hover:bg-surface-600 border-surface-600':
              selectedStepIndex !== index,
          }"
          @click="selectStep(index)"
        >
          <div class="flex items-center justify-between mb-2">
            <div class="font-medium text-sm text-surface-0">
              {{ step.stepName }}
            </div>
            <Tag
              :value="step.result"
              :severity="step.result === 'done' ? 'success' : 'warn'"
            />
          </div>

          <div class="text-xs text-surface-300 mb-1">
            Next:
            {{ step.result === "continue" ? step.nextStep : "Complete" }}
          </div>

          <div
            class="flex items-center justify-between text-xs text-surface-400"
          >
            <span>{{ step.findings.length }} findings</span>
            <span v-if="step.findings.length > 0" class="text-orange-400">
              {{ step.findings.map((f) => f.severity).join(", ") }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
