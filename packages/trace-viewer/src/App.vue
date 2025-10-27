<script setup lang="ts">
import { DetailView } from "@/components/DetailView";
import { Upload } from "@/components/Upload";
import { ChecksTable } from "@/components/ChecksTable";

import { useTrace } from "@/utils/useTrace";

const { hasTrace, currentView } = useTrace();

const handleTraceLoaded = () => {
  // Trace is loaded via the composable, no additional action needed
};
</script>

<template>
  <div id="app">
    <Upload v-if="!hasTrace" @trace-loaded="handleTraceLoaded" />
    <ChecksTable v-else-if="currentView === 'checks'" />
    <DetailView v-else />
  </div>
</template>
