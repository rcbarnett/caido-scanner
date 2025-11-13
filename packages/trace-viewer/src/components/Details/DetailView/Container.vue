<script setup lang="ts">
import { BreadcrumbNav } from "@/components/Details/Breadcrumb";
import { StateViewer } from "@/components/Details/StateViewer";
import { StepList } from "@/components/Details/StepList";
</script>

<template>
  <div class="flex flex-col gap-1">
    <!-- Breadcrumb -->
    <BreadcrumbNav />

    <!-- Main Content -->
    <div class="flex-1 flex gap-1 min-h-0">
      <StepList class="w-80" />
      <StateViewer class="flex-1" />
    </div>
  </div>
</template>
