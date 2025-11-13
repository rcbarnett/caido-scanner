<script setup lang="ts">
import { Upload } from "@/components/Home/Upload";

const emit = defineEmits<{
  traceLoaded: [];
}>();

const handleTraceLoaded = () => {
  emit("traceLoaded");
};
</script>

<template>
  <div>
    <Upload class="w-full h-full" @trace-loaded="handleTraceLoaded" />
  </div>
</template>
