import { ScanAggressivity } from "engine";
import type { ActiveConfig, PassiveConfig, Preset, UserConfig } from "shared";

import {
  PresetsStorage,
  type ProjectConfig,
  ProjectConfigStorage,
} from "../storage";
import type { BackendSDK } from "../types";

import { BALANCED_PRESET, HEAVY_PRESET, LIGHT_PRESET } from "./presets";

const createDefaultPassiveConfig = (): PassiveConfig => ({
  enabled: true,
  aggressivity: ScanAggressivity.LOW,
  inScopeOnly: true,
  concurrentChecks: 2,
  concurrentRequests: 3,
  overrides: [],
  severities: ["critical", "high", "medium", "low", "info"],
});

const createDefaultActiveConfig = (): ActiveConfig => ({
  overrides: [],
});

const createDefaultPresets = (): Preset[] => [
  LIGHT_PRESET,
  BALANCED_PRESET,
  HEAVY_PRESET,
];

export class ConfigStore {
  private static instance?: ConfigStore;

  private config: UserConfig;
  private sdk!: BackendSDK;
  private presetsStorage!: PresetsStorage;
  private projectConfigStorage!: ProjectConfigStorage;
  private currentProjectId?: string;
  private saveTimeout?: Timeout;

  private constructor() {
    const presets = createDefaultPresets();
    const lightPreset = presets[0];

    this.config = {
      passive: createDefaultPassiveConfig(),
      active: createDefaultActiveConfig(),
      presets,
    };

    if (lightPreset) {
      this.config.active.overrides = lightPreset.active;
      this.config.passive.overrides = lightPreset.passive;
    }
  }

  static get(): ConfigStore {
    if (!ConfigStore.instance) {
      ConfigStore.instance = new ConfigStore();
    }

    return ConfigStore.instance;
  }

  async initialize(sdk: BackendSDK): Promise<void> {
    this.sdk = sdk;
    this.presetsStorage = new PresetsStorage(sdk);
    this.projectConfigStorage = new ProjectConfigStorage(sdk);

    const project = await sdk.projects.getCurrent();
    this.currentProjectId = project?.getId();

    const savedPresets = await this.presetsStorage.load();
    if (savedPresets) {
      this.config.presets = savedPresets;
    } else {
      await this.presetsStorage.save(this.config.presets);
    }

    if (this.currentProjectId !== undefined) {
      await this.loadProjectConfig(this.currentProjectId);
    }
  }

  async switchProject(projectId: string | undefined): Promise<void> {
    this.currentProjectId = projectId;

    if (projectId !== undefined) {
      await this.loadProjectConfig(projectId);
    } else {
      this.config.passive = createDefaultPassiveConfig();
      this.config.active = createDefaultActiveConfig();
    }
  }

  private async loadProjectConfig(projectId: string): Promise<void> {
    const savedConfig = await this.projectConfigStorage.load(projectId);
    if (savedConfig !== undefined) {
      this.config.passive = savedConfig.passive;
      this.config.active = savedConfig.active;
      return;
    }

    const lightPreset = this.config.presets[0];
    if (lightPreset) {
      this.config.active.overrides = lightPreset.active;
      this.config.passive.overrides = lightPreset.passive;
    }
    this.saveProjectConfig();
  }

  private saveProjectConfig(): void {
    if (this.currentProjectId === undefined) return;

    if (this.saveTimeout !== undefined) {
      clearTimeout(this.saveTimeout);
    }

    this.saveTimeout = setTimeout(() => {
      if (this.currentProjectId === undefined) return;

      const projectConfig: ProjectConfig = {
        passive: this.config.passive,
        active: this.config.active,
      };

      this.projectConfigStorage.save(this.currentProjectId, projectConfig);
    }, 1000);
  }

  getUserConfig(): UserConfig {
    return { ...this.config };
  }

  updateUserConfig(config: Partial<UserConfig>): UserConfig {
    Object.assign(this.config, config);

    if (config.presets !== undefined) {
      this.presetsStorage.save(config.presets);
    }

    this.saveProjectConfig();
    this.sdk.api.send("config:updated", this.currentProjectId);

    return this.config;
  }
}
