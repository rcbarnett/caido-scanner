<script setup lang="ts">
import { Layout } from "@/components/Layout";
import { Upload } from "@/components/Upload";
import { useTrace } from "@/utils/useTrace";

const { hasTrace } = useTrace();

const handleTraceLoaded = () => {
  // Trace is loaded via the composable, no additional action needed
};
</script>

<template>
  <div id="app">
    <Upload v-if="!hasTrace" @trace-loaded="handleTraceLoaded" />
    <Layout v-else />
  </div>
</template>
