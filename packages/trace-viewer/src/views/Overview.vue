<script setup lang="ts">
import { BreadcrumbNav } from "@/components/Overview/Breadcrumb";
import { ChecksTable } from "@/components/Overview/ChecksTable";
</script>

<template>
  <div class="flex flex-col gap-1">
    <BreadcrumbNav />
    <ChecksTable class="size-full" />
  </div>
</template>
