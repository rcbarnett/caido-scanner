import path from "path";

import type { UserConfig } from "shared";

import type { BackendSDK } from "../types";

import { BaseStorage } from "./base";

export type ProjectConfig = Omit<UserConfig, "presets">;

export class ProjectConfigStorage extends BaseStorage {
  constructor(sdk: BackendSDK) {
    super(sdk);
  }

  private getFilePath(projectId: string): string {
    return path.join(
      this.getBasePath(),
      "config",
      "projects",
      projectId,
      "config.json",
    );
  }

  async load(projectId: string): Promise<ProjectConfig | undefined> {
    return this.readJson<ProjectConfig>(this.getFilePath(projectId));
  }

  async save(projectId: string, config: ProjectConfig): Promise<void> {
    try {
      await this.writeJson(this.getFilePath(projectId), config);
    } catch (error) {
      this.sdk.console.error(
        `Failed to save project config for ${projectId}: ${error}`,
      );
    }
  }
}
