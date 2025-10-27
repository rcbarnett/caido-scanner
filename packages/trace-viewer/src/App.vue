<script setup lang="ts">
import { Navbar } from "@/components/Navbar";
import { useProvideViewState, useViewState } from "@/composables/useViewState";
import Details from "@/views/Details.vue";
import Home from "@/views/Home.vue";
import Overview from "@/views/Overview.vue";

// Provide the view state at the root level
useProvideViewState();

const { currentView } = useViewState()!;
</script>

<template>
  <div class="w-screen h-screen flex flex-col gap-1 p-1">
    <Navbar />
    <Home v-if="currentView.kind === 'home'" class="flex-1 min-h-0" />
    <Overview
      v-else-if="currentView.kind === 'checks'"
      class="flex-1 min-h-0"
    />
    <Details
      v-else-if="currentView.kind === 'details'"
      class="flex-1 min-h-0"
    />
  </div>
</template>
