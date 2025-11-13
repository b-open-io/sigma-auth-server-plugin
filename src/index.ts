import { PublicKey } from "@bsv/sdk";
import type { BetterAuthPlugin, User } from "better-auth";
import {
	APIError,
	createAuthEndpoint,
	createAuthMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseAuthToken, verifyAuthToken } from "bitcoin-auth";
import { z } from "zod";

/**
 * Configuration options for the Sigma Auth plugin
 */
export interface SigmaPluginOptions {
	/**
	 * Optional BAP (Bitcoin Attestation Protocol) ID resolver
	 * Resolves a Bitcoin pubkey to a BAP ID and registers it
	 * @param pool Database connection pool (implementation-specific)
	 * @param userId User ID in your database
	 * @param pubkey Bitcoin public key
	 * @param register Whether to register the BAP ID
	 * @returns BAP ID or null if not found
	 */
	resolveBAPId?: (
		pool: any,
		userId: string,
		pubkey: string,
		register: boolean,
	) => Promise<string | null>;

	/**
	 * Optional database pool getter
	 * Returns a database connection pool for BAP ID resolution
	 */
	getPool?: () => any;

	/**
	 * Optional cache implementation for BAP ID caching
	 * Should provide get/set/delete methods for key-value storage
	 */
	cache?: {
		get: <T = any>(key: string) => Promise<T | null>;
		set: (key: string, value: any) => Promise<void>;
		delete?: (key: string) => Promise<void>;
	};

	/**
	 * Enable subscription tier support
	 * Adds subscriptionTier field to user and session
	 * @default false
	 */
	enableSubscription?: boolean;
}

export const sigma = (options?: SigmaPluginOptions): BetterAuthPlugin => ({
	id: "sigma",

	schema: {
		user: {
			fields: {
				pubkey: {
					type: "string",
					required: true,
					unique: true,
				},
				...(options?.enableSubscription
					? {
							subscriptionTier: {
								type: "string",
								required: false,
								defaultValue: "free",
							},
						}
					: {}),
			},
		},
		session: {
			fields: {
				...(options?.enableSubscription
					? {
							subscriptionTier: {
								type: "string",
								required: false,
							},
						}
					: {}),
			},
		},
	},

	hooks: {
		after: [
			{
				matcher: (ctx) => ctx.path === "/oauth2/token",
				handler: createAuthMiddleware(async (ctx) => {
					const body = ctx.body as Record<string, unknown>;
					const grantType = body.grant_type as string;

					// Only handle authorization_code grant (not refresh_token)
					if (grantType !== "authorization_code") {
						return;
					}

					// Check if token exchange was successful
					const responseBody = ctx.context.returned;
					if (
						!responseBody ||
						typeof responseBody !== "object" ||
						!("access_token" in responseBody)
					) {
						return; // Token exchange failed, skip BAP ID storage
					}

					// Only proceed if we have the necessary options
					if (!(options?.getPool && options?.cache)) {
						return;
					}

					try {
						const code = body.code as string;
						const clientId = body.client_id as string;
						const pool = options.getPool();

						// Get the consent_code from the authorization record
						const authResult = await pool.query(
							"SELECT consent_code, user_id FROM oauth_authorization WHERE code = $1 LIMIT 1",
							[code],
						);

						if (authResult.rows.length === 0) {
							console.warn(
								"⚠️ [OAuth Token] No authorization record found for code",
							);
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						const consentCode = authResult.rows[0].consent_code;
						const userId = authResult.rows[0].user_id;

						// Retrieve selected BAP ID from cache/KV
						const selectedBapId = await options.cache.get<string>(
							`consent:${consentCode}:bap_id`,
						);

						if (!selectedBapId) {
							console.warn("⚠️ [OAuth Token] No BAP ID selection found in KV");
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						// Get OAuth client's owner_bap_id
						const clients = await ctx.context.adapter.findMany({
							model: "oauthApplication",
							where: [{ field: "clientId", value: clientId }],
						});

						if (clients.length === 0) {
							console.warn("⚠️ [OAuth Token] OAuth client not found");
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						const client = clients[0] as { metadata?: { owner_bap_id?: string } };
						const oauthClientBapId = client.metadata?.owner_bap_id || clientId;

						// Store the selected BAP ID in oauth_client_identities
						await pool.query(
							`INSERT INTO oauth_client_identities (user_id, oauth_client_id, bap_id, updated_at)
							 VALUES ($1, $2, $3, NOW())
							 ON CONFLICT (user_id, oauth_client_id)
							 DO UPDATE SET bap_id = $3, updated_at = NOW()`,
							[userId, oauthClientBapId, selectedBapId],
						);

						console.log(
							`✅ [OAuth Token] Stored identity selection: user=${userId.substring(0, 15)}... client=${oauthClientBapId.substring(0, 15)}... bap=${selectedBapId.substring(0, 15)}...`,
						);

						// Clean up KV entry - use cache.delete if available, otherwise try direct method
						try {
							// @ts-ignore - cache might have a delete method
							if (typeof options.cache.delete === "function") {
								// @ts-ignore
								await options.cache.delete(`consent:${consentCode}:bap_id`);
							}
						} catch (e) {
							console.warn("⚠️ Could not delete consent KV entry:", e);
						}

						if (pool && typeof pool.end === "function") {
							await pool.end();
						}
					} catch (error) {
						console.error(
							"❌ [OAuth Token] Error storing identity selection:",
							error,
						);
					}
				}),
			},
		],
		before: [
			{
				matcher: (ctx) => ctx.path === "/oauth2/token",
				handler: createAuthMiddleware(async (ctx) => {
					const body = ctx.body as Record<string, unknown>;
					const grantType = body.grant_type as string;

					// Handle authorization_code grant type (exchange code for token)
					if (grantType === "authorization_code") {
						// Validate client authentication via Bitcoin signature
						const headers = new Headers(ctx.headers || {});
						const authToken = headers.get("x-auth-token");

						if (!authToken) {
							throw new APIError("UNAUTHORIZED", {
								message:
									"Missing X-Auth-Token header for client authentication",
							});
						}

						// Parse the auth token to extract pubkey
						const parsed = parseAuthToken(authToken);
						if (!parsed?.pubkey) {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid Bitcoin auth token format",
							});
						}

						// Get request body for signature verification
						const bodyString = new URLSearchParams(
							Object.entries(body).map(
								([k, v]) => [k, String(v)] as [string, string],
							),
						).toString();

						// Verify Bitcoin signature with body
						const verifyData = {
							requestPath: "/oauth2/token",
							timestamp: parsed.timestamp,
							body: bodyString,
						};

						const isValid = verifyAuthToken(authToken, verifyData, 5);
						if (!isValid) {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid Bitcoin signature",
							});
						}

						// Use pubkey as client_id, but verify client exists first
						const clientId = parsed.pubkey;

						// Verify this client is registered
						const clients = await ctx.context.adapter.findMany({
							model: "oauthApplication",
							where: [{ field: "clientId", value: clientId }],
						});

						if (clients.length === 0) {
							throw new APIError("UNAUTHORIZED", {
								message:
									"OAuth client not registered. Register the client first.",
							});
						}

						console.log(
							`✅ [OAuth Token] Client authenticated via Bitcoin signature (clientId: ${clientId.substring(0, 20)}...)`,
						);

						// Inject client_id into request body for Better Auth to process
						const modifiedBody = {
							...(ctx.body as Record<string, unknown>),
							client_id: clientId,
						};

						// Return modified context - let Better Auth handle:
						// - Authorization code lookup and validation
						// - PKCE verification
						// - redirect_uri validation
						// - Token generation and storage
						return {
							context: {
								...ctx,
								body: modifiedBody,
							},
						};
					}

					// Handle refresh_token grant type
					if (grantType === "refresh_token") {
						const refreshToken = body.refresh_token as string;

						if (!refreshToken) {
							throw new APIError("BAD_REQUEST", {
								message: "Missing refresh_token",
							});
						}

						// Validate client signature first
						const headers = new Headers(ctx.headers || {});
						const authToken = headers.get("x-auth-token");

						if (!authToken) {
							throw new APIError("UNAUTHORIZED", {
								message:
									"Missing X-Auth-Token header for client authentication",
							});
						}

						const parsed = parseAuthToken(authToken);
						if (!parsed?.pubkey) {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid Bitcoin auth token format",
							});
						}

						const bodyString = new URLSearchParams(
							Object.entries(body).map(
								([k, v]) => [k, String(v)] as [string, string],
							),
						).toString();

						const verifyData = {
							requestPath: "/oauth2/token",
							timestamp: parsed.timestamp,
							body: bodyString,
						};

						const isValid = verifyAuthToken(authToken, verifyData, 5);
						if (!isValid) {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid Bitcoin signature",
							});
						}

						// Use pubkey as client_id, but verify client exists first
						const clientId = parsed.pubkey;

						// Verify this client is registered
						const clients = await ctx.context.adapter.findMany({
							model: "oauthApplication",
							where: [{ field: "clientId", value: clientId }],
						});

						if (clients.length === 0) {
							throw new APIError("UNAUTHORIZED", {
								message:
									"OAuth client not registered. Register the client first.",
							});
						}

						console.log(
							`✅ [OAuth Token Refresh] Client authenticated via Bitcoin signature (clientId: ${clientId.substring(0, 20)}...)`,
						);

						// Inject client_id into request body for Better Auth to process
						const modifiedBody = {
							...(ctx.body as Record<string, unknown>),
							client_id: clientId,
						};

						// Return modified context - let Better Auth handle refresh token logic
						return {
							context: {
								...ctx,
								body: modifiedBody,
							},
						};
					}

					// Unknown grant type
					throw new APIError("BAD_REQUEST", {
						message: `Unsupported grant_type: ${grantType}`,
					});
				}),
			},
		],
	},

	endpoints: {
		signInSigma: createAuthEndpoint(
			"/sign-in/sigma",
			{
				method: "POST",
				body: z.optional(z.object({})),
			},
			async (ctx) => {
				// Get auth token from header
				const authToken = ctx.headers?.get("x-auth-token");
				if (!authToken) {
					throw new APIError("UNAUTHORIZED", {
						message: "No auth token provided",
					});
				}

				// Parse the auth token
				const parsed = parseAuthToken(authToken);
				if (!(parsed && parsed.pubkey)) {
					throw new APIError("BAD_REQUEST", {
						message: "Invalid auth token format",
					});
				}

				// Verify the auth token
				// The token was signed without a body, so we verify without a body
				const verifyData = {
					requestPath: "/api/auth/sign-in/sigma",
					timestamp: parsed.timestamp, // Use the timestamp from the token
				};

				console.log("Verifying auth token with:", verifyData);

				const isValid = verifyAuthToken(authToken, verifyData, 5);

				if (!isValid) {
					throw new APIError("UNAUTHORIZED", {
						message: "Invalid auth token signature",
					});
				}

				// Extract pubkey from the parsed token
				const pubkey = parsed.pubkey;

				// Find or create user by pubkey
				interface UserWithPubkey extends User {
					pubkey: string;
				}

				// Try to find user by pubkey first
				console.log("Looking for user with pubkey:", pubkey);

				const users = await ctx.context.adapter.findMany<UserWithPubkey>({
					model: "user",
					where: [{ field: "pubkey", value: pubkey }],
				});

				console.log("Found users by pubkey:", users.length);

				let user = users[0] as UserWithPubkey | undefined;

				if (!user) {
					// Create new user with pubkey (no email)
					console.log("Creating new user with pubkey:", pubkey);

					try {
						user = (await ctx.context.adapter.create({
							model: "user",
							data: {
								name: PublicKey.fromString(pubkey).toAddress(),
								pubkey,
								emailVerified: false,
								createdAt: new Date(),
								updatedAt: new Date(),
							},
						})) as UserWithPubkey;
					} catch (error: any) {
						console.error("Error creating user:", error);

						// If duplicate key error, try to find the user again by pubkey
						if (error.code === "23505") {
							console.log(
								"User already exists, attempting to find again by pubkey...",
							);
							const existingUsers =
								await ctx.context.adapter.findMany<UserWithPubkey>({
									model: "user",
									where: [{ field: "pubkey", value: pubkey }],
								});

							user = existingUsers[0] as UserWithPubkey | undefined;

							if (!user) {
								throw new APIError("INTERNAL_SERVER_ERROR", {
									message: "User exists but cannot be found",
								});
							}
						} else {
							throw error;
						}
					}
				}

				// REMOVED: Subscription verification from sign-in flow
				// NFT subscription verification is available via separate endpoint:
				// GET /api/subscription/status (requires authentication)
				// This keeps auth flow fast and decouples features

				// Resolve BAP ID if resolver is provided
				if (options?.resolveBAPId && options?.getPool) {
					const pool = options.getPool();
					console.log(
						`🔑 [SIGN-IN] Resolving pubkey to BAP ID: ${pubkey.substring(0, 30)}...`,
					);

					// Check cache if available
					const cacheKey = `bap:resolve:${pubkey}`;
					let cachedBapId: string | null = null;
					if (options?.cache) {
						try {
							cachedBapId = await options.cache.get<string>(cacheKey);
							if (cachedBapId) {
								console.log(
									`✅ [SIGN-IN] Found cached BAP ID: ${cachedBapId.substring(0, 15)}...`,
								);
							}
						} catch (error) {
							console.warn("⚠️ [SIGN-IN] Cache lookup failed:", error);
						}
					}

					// CRITICAL: Always call resolveBAPId - it has its own caching
					// Bypassing with cachedBapId causes issues if registration is needed
					const bapId = await options.resolveBAPId(pool, user.id, pubkey, true);

					// Close pool if it has an end method
					if (pool && typeof pool.end === "function") {
						await pool.end();
					}

					if (bapId) {
						console.log(
							`✅ BAP ID resolved and registered: ${bapId.substring(0, 20)}...`,
						);

						// Re-fetch user to get updated profile data
						const updatedUsers =
							await ctx.context.adapter.findMany<UserWithPubkey>({
								model: "user",
								where: [{ field: "id", value: user.id }],
							});
						if (updatedUsers[0]) {
							user = updatedUsers[0];
							console.log(`✅ User profile refreshed with name: ${user.name}`);
						}
					} else {
						console.warn(
							"⚠️ BAP ID resolution failed - user may not have on-chain identity yet",
						);
					}
				}

				// Create session - matches SIWE pattern exactly
				const session = await ctx.context.internalAdapter.createSession(
					user.id,
					ctx,
				);

				if (!session) {
					throw new APIError("INTERNAL_SERVER_ERROR", {
						message: "Internal Server Error",
						status: 500,
					});
				}

				await setSessionCookie(ctx, { session, user });

				return ctx.json({
					token: session.token,
					user: {
						id: user.id,
						pubkey: user.pubkey,
						name: user.name,
					},
				});
			},
		),
	},
});
