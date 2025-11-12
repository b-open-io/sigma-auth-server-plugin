/**
 * OAuth code storage implementations
 */

import type { OAuthCodeData, OAuthCodeStorage } from "./types";

/**
 * In-memory OAuth code storage
 * NOT SUITABLE FOR PRODUCTION - codes don't persist across restarts
 * Use for development/testing only
 */
export class InMemoryOAuthCodeStorage implements OAuthCodeStorage {
	private codes: Map<string, { data: OAuthCodeData; expiresAt: number }> =
		new Map();

	async set(
		code: string,
		data: OAuthCodeData,
		expiresIn: number,
	): Promise<void> {
		const expiresAt = Date.now() + expiresIn * 1000;
		this.codes.set(code, { data, expiresAt });

		// Clean up expired codes periodically
		setTimeout(() => this.cleanup(), expiresIn * 1000);
	}

	async get(code: string): Promise<OAuthCodeData | null> {
		const entry = this.codes.get(code);
		if (!entry) return null;

		if (Date.now() > entry.expiresAt) {
			this.codes.delete(code);
			return null;
		}

		// Delete after retrieval (one-time use)
		this.codes.delete(code);
		return entry.data;
	}

	async delete(code: string): Promise<void> {
		this.codes.delete(code);
	}

	private cleanup(): void {
		const now = Date.now();
		for (const [code, entry] of this.codes.entries()) {
			if (now > entry.expiresAt) {
				this.codes.delete(code);
			}
		}
	}
}

/**
 * Vercel KV storage adapter
 * Requires @vercel/kv package
 */
export class VercelKVOAuthCodeStorage implements OAuthCodeStorage {
	constructor(private kv: any) {}

	async set(
		code: string,
		data: OAuthCodeData,
		expiresIn: number,
	): Promise<void> {
		await this.kv.set(`oauth:codes:${code}`, JSON.stringify(data), {
			ex: expiresIn,
		});
	}

	async get(code: string): Promise<OAuthCodeData | null> {
		const stored = await this.kv.get(`oauth:codes:${code}`);
		if (!stored) return null;

		// Delete after retrieval
		await this.kv.del(`oauth:codes:${code}`);

		return typeof stored === "string" ? JSON.parse(stored) : stored;
	}

	async delete(code: string): Promise<void> {
		await this.kv.del(`oauth:codes:${code}`);
	}
}

/**
 * Redis storage adapter
 * Requires ioredis or redis package
 */
export class RedisOAuthCodeStorage implements OAuthCodeStorage {
	constructor(private redis: any) {}

	async set(
		code: string,
		data: OAuthCodeData,
		expiresIn: number,
	): Promise<void> {
		await this.redis.set(
			`oauth:codes:${code}`,
			JSON.stringify(data),
			"EX",
			expiresIn,
		);
	}

	async get(code: string): Promise<OAuthCodeData | null> {
		const stored = await this.redis.get(`oauth:codes:${code}`);
		if (!stored) return null;

		// Delete after retrieval
		await this.redis.del(`oauth:codes:${code}`);

		return JSON.parse(stored);
	}

	async delete(code: string): Promise<void> {
		await this.redis.del(`oauth:codes:${code}`);
	}
}
