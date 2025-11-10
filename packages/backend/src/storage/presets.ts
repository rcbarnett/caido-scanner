import path from "path";

import type { Preset } from "shared";

import type { BackendSDK } from "../types";

import { BaseStorage } from "./base";

export class PresetsStorage extends BaseStorage {
  constructor(sdk: BackendSDK) {
    super(sdk);
  }

  private getFilePath(): string {
    return path.join(this.getBasePath(), "config", "presets.json");
  }

  async load(): Promise<Preset[] | undefined> {
    return this.readJson<Preset[]>(this.getFilePath());
  }

  async save(presets: Preset[]): Promise<void> {
    try {
      await this.writeJson(this.getFilePath(), presets);
    } catch (error) {
      this.sdk.console.error(`Failed to save presets: ${error}`);
    }
  }
}
