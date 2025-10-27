<script setup lang="ts">
import Breadcrumb from "primevue/breadcrumb";
import { computed } from "vue";

import { useTrace } from "@/composables/useTrace";

const { selectedCheck, goBackToChecks } = useTrace();

const items = computed(() => [
  {
    label: "Checks",
    command: goBackToChecks,
  },
  {
    label: selectedCheck.value?.checkId || "Details",
  },
]);

const home = {
  icon: "fas fa-home",
  command: goBackToChecks,
};
</script>

<template>
  <div class="p-4 border-b border-surface-600 bg-surface-800">
    <Breadcrumb :model="items" :home="home" />
  </div>
</template>
