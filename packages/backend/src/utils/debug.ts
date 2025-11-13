import { type ExecutionHistory } from "engine";

export const packExecutionHistory = (history: ExecutionHistory): string => {
  const json = JSON.stringify(history);
  return btoa(json);
};
