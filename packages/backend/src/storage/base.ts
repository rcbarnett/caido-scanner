import { mkdir, readdir, readFile, rm, writeFile } from "fs/promises";
import path from "path";

import type { BackendSDK } from "../types";

export abstract class BaseStorage {
  protected sdk: BackendSDK;

  constructor(sdk: BackendSDK) {
    this.sdk = sdk;
  }

  protected getBasePath(): string {
    return this.sdk.meta.path();
  }

  protected async readJson<T>(filePath: string): Promise<T | undefined> {
    try {
      const fileData = await readFile(filePath, "utf-8");
      return JSON.parse(fileData) as T;
    } catch {
      return undefined;
    }
  }

  protected async writeJson<T>(filePath: string, data: T): Promise<void> {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify(data, null, 2));
  }

  protected async deleteFile(filePath: string): Promise<void> {
    await rm(filePath);
  }

  protected async listJsonFiles<T>(
    dirPath: string,
  ): Promise<{ file: string; data: T }[]> {
    try {
      const files = await readdir(dirPath);
      const results: { file: string; data: T }[] = [];

      for (const file of files) {
        if (!file.endsWith(".json")) continue;

        const data = await this.readJson<T>(path.join(dirPath, file));
        if (data !== undefined) {
          results.push({ file, data });
        }
      }

      return results;
    } catch {
      return [];
    }
  }
}
