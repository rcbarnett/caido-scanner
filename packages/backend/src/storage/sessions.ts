import path from "path";

import type { Session } from "shared";

import type { BackendSDK } from "../types";

import { BaseStorage } from "./base";

export class SessionsStorage extends BaseStorage {
  constructor(sdk: BackendSDK) {
    super(sdk);
  }

  private getSessionDir(projectId: string): string {
    return path.join(this.getBasePath(), "sessions", projectId);
  }

  private getSessionFilePath(projectId: string, sessionId: string): string {
    return path.join(this.getSessionDir(projectId), `${sessionId}.json`);
  }

  async load(
    projectId: string,
    sessionId: string,
  ): Promise<Session | undefined> {
    return this.readJson<Session>(
      this.getSessionFilePath(projectId, sessionId),
    );
  }

  async list(projectId: string): Promise<Session[]> {
    const results = await this.listJsonFiles<Session>(
      this.getSessionDir(projectId),
    );

    return results.map((result) => result.data);
  }

  async save(projectId: string, session: Session): Promise<void> {
    try {
      await this.writeJson(
        this.getSessionFilePath(projectId, session.id),
        session,
      );
    } catch (error) {
      this.sdk.console.error(`Failed to save session ${session.id}: ${error}`);
    }
  }

  async delete(projectId: string, sessionId: string): Promise<void> {
    try {
      await this.deleteFile(this.getSessionFilePath(projectId, sessionId));
    } catch (error) {
      this.sdk.console.error(`Failed to delete session ${sessionId}: ${error}`);
    }
  }
}
