<script setup lang="ts">
import Card from "primevue/card";
import Tag from "primevue/tag";

import { useTrace } from "@/composables/useTrace";

const { parsedTrace, selectedCheckIndex, selectCheck } = useTrace();
</script>

<template>
  <div class="h-full flex flex-col">
    <Card class="h-full" :pt="{ content: 'h-full flex flex-col' }">
      <template #title>
        <div>
          <h2 class="text-lg font-semibold text-surface-0">Checks</h2>
          <p class="text-sm text-surface-300">{{ parsedTrace.totalChecks }} checks, {{ parsedTrace.totalSteps }} steps</p>
        </div>
      </template>

      <template #content>
        <div class="flex-1 overflow-y-auto">
          <div class="space-y-2">
            <div
              v-for="(check, index) in parsedTrace.executionHistory"
              :key="`${check.checkId}-${check.targetRequestId}`"
              class="p-3 rounded-lg cursor-pointer transition-colors border"
              :class="{
                'bg-primary-900/20 border-primary-500': selectedCheckIndex === index,
                'bg-surface-700 hover:bg-surface-600 border-surface-600': selectedCheckIndex !== index
              }"
              @click="selectCheck(index)"
            >
              <div class="flex items-center justify-between mb-2">
                <div class="font-medium text-sm text-surface-0 truncate">
                  {{ check.checkId }}
                </div>
                <Tag
                  :value="check.status"
                  :severity="check.status === 'completed' ? 'success' : 'danger'"
                />
              </div>
              
              <div class="text-xs text-surface-300 mb-1">
                Target: {{ check.targetRequestId }}
              </div>
              
              <div class="flex items-center justify-between text-xs text-surface-400">
                <span>{{ check.steps.length }} steps</span>
                <span v-if="check.status === 'failed'" class="text-red-400">
                  {{ check.error.message }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
