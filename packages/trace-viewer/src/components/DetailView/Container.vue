<script setup lang="ts">
import { BreadcrumbNav } from "@/components/Breadcrumb";
import { StateViewer } from "@/components/StateViewer";
import { StepList } from "@/components/StepList";
</script>

<template>
  <div class="h-screen flex flex-col bg-surface-800">
    <!-- Breadcrumb -->
    <BreadcrumbNav />

    <!-- Main Content -->
    <div class="flex-1 flex overflow-hidden">
      <!-- Left Panel - Step List -->
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
