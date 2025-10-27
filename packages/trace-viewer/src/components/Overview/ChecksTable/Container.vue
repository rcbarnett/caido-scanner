<script setup lang="ts">
import Card from "primevue/card";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Tag from "primevue/tag";

import { useTrace } from "@/utils/useTrace";

const { parsedTrace, selectCheck } = useTrace();

const getSeverityColor = (status: string) => {
  return status === "completed" ? "success" : "danger";
};

const onRowSelect = (event: any) => {
  const index = parsedTrace.executionHistory.findIndex(
    (check) =>
      check.checkId === event.data.checkId &&
      check.targetRequestId === event.data.targetRequestId,
  );
  if (index !== -1) {
    selectCheck(index);
  }
};
</script>

<template>
  <div class="flex flex-col min-h-0">
    <Card class="h-full" :pt="{ content: 'h-full flex flex-col' }">
      <template #title>
        <div>
          <h2 class="text-lg font-semibold text-surface-0">Checks</h2>
          <p class="text-sm text-surface-300">
            {{ parsedTrace.totalChecks }} checks,
            {{ parsedTrace.totalSteps }} steps,
            {{ parsedTrace.totalFindings }} findings
          </p>
        </div>
      </template>

      <template #content>
        <div class="flex-1 overflow-hidden">
          <DataTable
            :value="parsedTrace.executionHistory"
            :paginator="true"
            :rows="20"
            :rows-per-page-options="[10, 20, 50, 100]"
            paginator-template="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink CurrentPageReport RowsPerPageDropdown"
            current-page-report-template="Showing {first} to {last} of {totalRecords} checks"
            class="h-full"
            :pt="{
              table: 'h-full',
              tbody: 'h-full',
              wrapper: 'h-full flex flex-col',
              content: 'flex-1 overflow-auto',
            }"
            selection-mode="single"
            data-key="checkId"
            @row-click="onRowSelect"
          >
            <Column field="checkId" header="Check ID" sortable>
              <template #body="{ data }">
                <div class="font-medium text-surface-0">{{ data.checkId }}</div>
              </template>
            </Column>

            <Column field="targetRequestId" header="Target Request" sortable>
              <template #body="{ data }">
                <div class="text-sm text-surface-300">
                  {{ data.targetRequestId }}
                </div>
              </template>
            </Column>

            <Column field="status" header="Status" sortable>
              <template #body="{ data }">
                <Tag
                  :value="data.status"
                  :severity="getSeverityColor(data.status)"
                />
              </template>
            </Column>

            <Column field="steps.length" header="Steps" sortable>
              <template #body="{ data }">
                <div class="text-sm text-surface-300">
                  {{ data.steps.length }}
                </div>
              </template>
            </Column>

            <Column header="Findings">
              <template #body="{ data }">
                <div class="text-sm text-surface-300">
                  {{
                    data.steps.reduce(
                      (sum: number, step: any) => sum + step.findings.length,
                      0,
                    )
                  }}
                </div>
              </template>
            </Column>

            <Column
              v-if="
                parsedTrace.executionHistory.some((c) => c.status === 'failed')
              "
              header="Error"
            >
              <template #body="{ data }">
                <div
                  v-if="data.status === 'failed'"
                  class="text-sm text-red-400 truncate max-w-xs"
                >
                  {{ data.error.message }}
                </div>
                <div v-else class="text-sm text-surface-400">-</div>
              </template>
            </Column>
          </DataTable>
        </div>
      </template>
    </Card>
  </div>
</template>
