<script setup lang="ts">
import Button from "primevue/button";
import { type Session } from "shared";
import { computed } from "vue";

import { useForm } from "./useForm";

import { useScannerService } from "@/services/scanner";

const props = defineProps<{
  session: Session;
}>();

const { getStatusColor, onCancel, onDelete, isCancelling, isDeleting } =
  useForm(props);

const scannerService = useScannerService();

const hasExecutionTrace = computed(() => {
  if (props.session.kind === "Done" || props.session.kind === "Interrupted") {
    return props.session.hasExecutionTrace;
  }

  return false;
});

const onDownloadTrace = () => {
  scannerService.downloadExecutionTrace(props.session.id);
};
</script>

<template>
  <div class="flex items-center justify-between gap-4 px-4 pt-4">
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2">
        <span class="text-base font-medium">{{ session.title }}</span>
        <span class="text-xs text-surface-400 font-mono">{{ session.id }}</span>
      </div>
      <div class="flex items-center gap-2">
        <div
          :class="['w-2 h-2 rounded-full', getStatusColor(session.kind)]"
        ></div>
        <span
          :class="['text-xs rounded text-surface-100 uppercase tracking-wide']"
        >
          <span :class="{ shimmer: session.kind === 'Running' }">{{
            session.kind
          }}</span>
          <span
            v-if="session.kind === 'Interrupted' && session.reason"
            class="text-xs text-surface-400 normal-case ml-1"
          >
            ({{ session.reason }})
          </span>
        </span>
      </div>
    </div>

    <div class="flex items-center gap-2">
      <Button
        v-if="session.kind === 'Running'"
        label="Cancel"
        severity="danger"
        :loading="isCancelling"
        outlined
        size="small"
        @click="onCancel"
      />

      <Button
        v-if="hasExecutionTrace"
        label="Download Trace"
        severity="contrast"
        outlined
        size="small"
        icon="fas fa-download"
        @click="onDownloadTrace"
      />

      <Button
        label="Delete"
        severity="danger"
        :loading="isDeleting"
        outlined
        size="small"
        @click="onDelete"
      />
    </div>
  </div>
</template>
