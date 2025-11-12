import type { ScanRunnable } from "engine";
import type { QueueTask } from "shared";

import type { TaskQueue } from "../utils/task-queue";

export class QueueStore {
  private static instance?: QueueStore;

  private tasks: QueueTask[];
  private cancelFunctions: Map<string, () => void>;
  private passiveTaskQueue?: TaskQueue;

  private constructor() {
    this.tasks = [];
    this.cancelFunctions = new Map();
  }

  static get(): QueueStore {
    if (!QueueStore.instance) {
      QueueStore.instance = new QueueStore();
    }

    return QueueStore.instance;
  }

  setPassiveTaskQueue(queue: TaskQueue): void {
    this.passiveTaskQueue = queue;
  }

  addTask(id: string, requestID: string): QueueTask {
    const task: QueueTask = {
      id,
      requestID,
      status: "pending",
    };

    this.tasks.push(task);
    return task;
  }

  addActiveRunnable(id: string, runnable: ScanRunnable): void {
    this.cancelFunctions.set(id, () => runnable.cancel("Cancelled"));
  }

  removeActiveRunnable(id: string): void {
    this.cancelFunctions.delete(id);
  }

  updateTaskStatus(
    id: string,
    status: QueueTask["status"],
  ): QueueTask | undefined {
    const task = this.tasks.find((t) => t.id === id);
    if (task !== undefined) {
      task.status = status;
    }
    return task;
  }

  removeTask(id: string): boolean {
    const index = this.tasks.findIndex((t) => t.id === id);
    if (index !== -1) {
      this.tasks.splice(index, 1);
      return true;
    }

    return false;
  }

  getTasks(): QueueTask[] {
    return [...this.tasks];
  }

  getTask(id: string): QueueTask | undefined {
    return this.tasks.find((t) => t.id === id);
  }

  clearTasks(): void {
    for (const cancelFunction of this.cancelFunctions.values()) {
      cancelFunction();
    }
    this.cancelFunctions.clear();

    this.passiveTaskQueue?.clear();
    this.tasks = [];
  }
}
