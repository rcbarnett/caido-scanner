<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Message from "primevue/message";
import { ref } from "vue";

import { useTrace } from "@/utils/useTrace";

const emit = defineEmits<{
  traceLoaded: [];
}>();

const { loadTrace } = useTrace();

const dropZone = ref<HTMLElement>();
const fileInput = ref<HTMLInputElement>();
const isDragOver = ref(false);
const isLoading = ref(false);
const error = ref<string>("");

const handleFileSelect = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (file) {
    processFile(file);
  }
};

const handleDrop = (event: DragEvent) => {
  isDragOver.value = false;
  const file = event.dataTransfer?.files[0];
  if (file) {
    processFile(file);
  }
};

const processFile = async (file: File) => {
  if (file === undefined) return;

  isLoading.value = true;
  error.value = "";

  try {
    const content = await file.text();
    const result = loadTrace(content);

    if (result.success) {
      emit("traceLoaded");
    } else {
      error.value =
        result.error !== undefined && result.error !== null
          ? result.error
          : "Failed to load trace";
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to read file";
  } finally {
    isLoading.value = false;
  }
};
</script>

<template>
  <div class="flex items-center justify-center min-h-screen bg-surface-800">
    <div class="w-full max-w-md">
      <Card class="p-8">
        <template #title>
          <div class="text-center">
            <h1 class="text-3xl font-bold text-surface-0 mb-2">Trace Viewer</h1>
            <p class="text-surface-300">
              Upload a trace file to explore execution history
            </p>
          </div>
        </template>

        <template #content>
          <div
            ref="dropZone"
            class="border-2 border-dashed border-surface-600 rounded-lg p-8 text-center transition-colors"
            :class="{
              'border-primary-400 bg-primary-900/20': isDragOver,
              'border-red-400 bg-red-900/20': error,
            }"
            @dragover.prevent="isDragOver = true"
            @dragleave.prevent="isDragOver = false"
            @drop.prevent="handleDrop"
          >
            <div v-if="!isLoading" class="space-y-4">
              <div class="text-6xl text-surface-400">📁</div>
              <div>
                <p class="text-lg font-medium text-surface-0">
                  {{ error ? "Upload failed" : "Drop your trace file here" }}
                </p>
                <p class="text-sm text-surface-300 mt-1">
                  {{ error || "or click to browse files" }}
                </p>
              </div>
              <input
                ref="fileInput"
                type="file"
                accept=".txt,.json"
                class="hidden"
                @change="handleFileSelect"
              />
              <Button
                label="Choose File"
                icon="fas fa-upload"
                @click="fileInput?.click()"
              />
            </div>

            <div v-else class="space-y-4">
              <div class="text-6xl text-primary-400">⏳</div>
              <p class="text-lg font-medium text-surface-0">
                Processing trace...
              </p>
            </div>
          </div>

          <Message v-if="error" severity="error" :closable="false" class="mt-4">
            {{ error }}
          </Message>
        </template>
      </Card>
    </div>
  </div>
</template>
