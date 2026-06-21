import type { Result } from "@dust-tt/client";
import { Err, Ok } from "@dust-tt/client";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { jwtDecode } from "jwt-decode";

import { normalizeError } from "./errors.js";

const SERVICE_NAME = "dust-cli";
const ACCESS_TOKEN_KEY = "access_token";
const REFRESH_TOKEN_KEY = "refresh_token";
const WORKSPACE_KEY = "workspace_sid";
const REGION_KEY = "region";

interface JWTPayload {
  exp: number;
  [key: string]: any;
}

// Credential backend interface matching the keytar API surface we use
interface CredentialBackend {
  setPassword(service: string, account: string, password: string): Promise<void>;
  getPassword(service: string, account: string): Promise<string | null>;
  deletePassword(service: string, account: string): Promise<boolean>;
}

// File-based fallback for headless environments without D-Bus/libsecret
function createFileBackend(): CredentialBackend {
  const dir = join(homedir(), ".dust-cli");
  const filePath = join(dir, "credentials.json");

  function readStore(): Record<string, Record<string, string>> {
    try {
      if (existsSync(filePath)) {
        return JSON.parse(readFileSync(filePath, "utf-8"));
      }
    } catch {
      // Corrupted file — start fresh
    }
    return {};
  }

  function writeStore(store: Record<string, Record<string, string>>): void {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    writeFileSync(filePath, JSON.stringify(store, null, 2), { mode: 0o600 });
  }

  return {
    async setPassword(service, account, password) {
      const store = readStore();
      if (!store[service]) {
        store[service] = {};
      }
      store[service][account] = password;
      writeStore(store);
    },
    async getPassword(service, account) {
      const store = readStore();
      return store[service]?.[account] ?? null;
    },
    async deletePassword(service, account) {
      const store = readStore();
      if (store[service]?.[account] !== undefined) {
        delete store[service][account];
        writeStore(store);
        return true;
      }
      return false;
    },
  };
}

let cachedBackend: CredentialBackend | null = null;

async function getBackend(): Promise<CredentialBackend> {
  if (cachedBackend) {
    return cachedBackend;
  }
  try {
    const keytar = await import("keytar");
    // Probe keytar to ensure D-Bus is available
    await keytar.default.findCredentials("__dust_probe__");
    cachedBackend = keytar.default;
  } catch {
    cachedBackend = createFileBackend();
  }
  return cachedBackend;
}

/**
 * Securely stores and retrieves authentication tokens.
 * Uses the system keychain (keytar) when available, otherwise falls back
 * to a file-based store at ~/.dust-cli/credentials.json.
 */
export const TokenStorage = {
  async saveTokens(accessToken: string, refreshToken: string): Promise<void> {
    const backend = await getBackend();
    await backend.setPassword(SERVICE_NAME, ACCESS_TOKEN_KEY, accessToken);
    await backend.setPassword(SERVICE_NAME, REFRESH_TOKEN_KEY, refreshToken);
  },

  async getAccessToken(): Promise<string | null> {
    const backend = await getBackend();
    return backend.getPassword(SERVICE_NAME, ACCESS_TOKEN_KEY);
  },

  async getRefreshToken(): Promise<string | null> {
    const backend = await getBackend();
    return backend.getPassword(SERVICE_NAME, REFRESH_TOKEN_KEY);
  },

  async hasValidAccessToken(): Promise<Result<boolean, Error>> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      return new Err(new Error("No access token found"));
    }

    // API keys don't expire
    if (accessToken.startsWith("sk-")) {
      return new Ok(true);
    }

    let decoded: JWTPayload;
    try {
      decoded = jwtDecode<JWTPayload>(accessToken);
    } catch (error) {
      return new Err(normalizeError(error));
    }

    const currentTime = Math.floor(Date.now() / 1000);
    return new Ok(decoded.exp > currentTime);
  },

  async saveWorkspaceId(workspaceId: string): Promise<void> {
    const backend = await getBackend();
    await backend.setPassword(SERVICE_NAME, WORKSPACE_KEY, workspaceId);
  },

  async getWorkspaceId(): Promise<string | null> {
    const backend = await getBackend();
    return backend.getPassword(SERVICE_NAME, WORKSPACE_KEY);
  },

  async saveRegion(region: string): Promise<void> {
    const backend = await getBackend();
    await backend.setPassword(SERVICE_NAME, REGION_KEY, region);
  },

  async getRegion(): Promise<string | null> {
    const backend = await getBackend();
    return backend.getPassword(SERVICE_NAME, REGION_KEY);
  },

  async clearTokens(): Promise<void> {
    const backend = await getBackend();
    await backend.deletePassword(SERVICE_NAME, ACCESS_TOKEN_KEY);
    await backend.deletePassword(SERVICE_NAME, REFRESH_TOKEN_KEY);
    await backend.deletePassword(SERVICE_NAME, WORKSPACE_KEY);
    await backend.deletePassword(SERVICE_NAME, REGION_KEY);
  },
};

export default TokenStorage;
