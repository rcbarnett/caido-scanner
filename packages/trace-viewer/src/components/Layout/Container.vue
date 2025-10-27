<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";

import { CheckList } from "@/components/CheckList";
import { StepList } from "@/components/StepList";
import { StateViewer } from "@/components/StateViewer";
import { useTrace } from "@/utils/useTrace";

const { parsedTrace, clearTrace } = useTrace();
</script>

<template>
  <div class="h-screen flex flex-col bg-surface-800">
    <!-- Header -->
    <Card class="rounded-none border-0 border-b border-surface-600">
      <template #content>
        <div class="px-6 py-4">
          <div class="flex items-center justify-between">
            <div>
              <h1 class="text-xl font-semibold text-surface-0">Trace Viewer</h1>
              <p class="text-sm text-surface-300">
                {{ parsedTrace.totalChecks }} checks • {{ parsedTrace.totalSteps }} steps • {{ parsedTrace.totalFindings }} findings
              </p>
            </div>
            <Button
              label="Load New Trace"
              icon="fas fa-refresh"
              severity="secondary"
              @click="clearTrace"
            />
          </div>
        </div>
      </template>
    </Card>

    <!-- Main Content -->
    <div class="flex-1 flex overflow-hidden">
      <!-- Left Panel - Check List -->
      <div class="w-80 border-r border-surface-600">
        <CheckList />
      </div>

      <!-- Middle Panel - Step List -->
      <div class="w-80 border-r border-surface-600">
        <StepList />
      </div>

      <!-- Right Panel - State Viewer -->
      <div class="flex-1">
        <StateViewer />
      </div>
    </div>
  </div>
</template>
