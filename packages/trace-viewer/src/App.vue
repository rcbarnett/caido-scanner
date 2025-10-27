<script setup lang="ts">
import { Navbar } from "@/components/Navbar";
import { useTrace } from "@/utils/useTrace";
import Details from "@/views/Details.vue";
import Home from "@/views/Home.vue";
import Overview from "@/views/Overview.vue";

const { currentView } = useTrace();
</script>

<template>
  <div class="w-screen h-screen flex flex-col gap-4 p-1">
    <Navbar />
    <Home v-if="currentView.kind === 'home'" class="flex-1" />
    <Overview v-else-if="currentView.kind === 'checks'" class="flex-1" />
    <Details v-else-if="currentView.kind === 'details'" class="flex-1" />
  </div>
</template>
