import { PublicKey } from "@bsv/sdk";
import type { Pool } from "@neondatabase/serverless";
import type { BetterAuthPlugin, User } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { createAuthMiddleware } from "better-auth/plugins";
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
		pool: Pool,
		userId: string,
		pubkey: string,
		register: boolean,
	) => Promise<string | null>;

	/**
	 * Optional database pool getter
	 * Returns a database connection pool for BAP ID resolution
	 */
	getPool?: () => Pool;

	/**
	 * Optional cache implementation for BAP ID caching
	 * Should provide get/set/delete methods for key-value storage
	 */
	cache?: {
		get: <T = unknown>(key: string) => Promise<T | null>;
		set: (key: string, value: unknown) => Promise<void>;
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
		oauthAccessToken: {
			fields: {
				selectedBapId: {
					type: "string",
					required: false,
				},
			},
		},
	},

	hooks: {
		after: [
			{
				matcher: (ctx) => ctx.path === "/oauth2/token",
				handler: createAuthMiddleware(async (ctx) => {
					console.log(
						"🔵 [Sigma Plugin] AFTER hook triggered for /oauth2/token",
					);
					const body = ctx.body as Record<string, unknown>;
					const grantType = body.grant_type as string;
					console.log(`🔵 [Sigma Plugin] Grant type: ${grantType}`);

					// Only handle authorization_code grant (not refresh_token)
					if (grantType !== "authorization_code") {
						console.log(
							"🔵 [Sigma Plugin] Skipping - not authorization_code grant",
						);
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
						const pool = options.getPool();

						// Get consent_code from Better Auth's KV storage
						// Better Auth stores authorization state at key: oauth:code:{code}
						const authStateKey = `oauth:code:${code}`;
						const authState = await options.cache.get<{
							consentCode?: string;
							userId?: string;
						}>(authStateKey);

						if (!authState?.consentCode) {
							console.warn(
								"⚠️ [OAuth Token] No consent code found for authorization code",
							);
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						const consentCode = authState.consentCode;
						const userId = authState.userId;

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

						// Get the access token from response
						const accessToken = (responseBody as { access_token: string })
							.access_token;

						// Update the oauthAccessToken record with the selected BAP ID
						await ctx.context.adapter.update({
							model: "oauthAccessToken",
							where: [{ field: "accessToken", value: accessToken }],
							update: {
								selectedBapId,
							},
						});

						console.log(
							`✅ [OAuth Token] Stored BAP ID in access token: user=${userId ? `${userId.substring(0, 15)}...` : "unknown"} bap=${selectedBapId.substring(0, 15)}...`,
						);

						// Clean up KV entry if delete method is available
						if (options.cache.delete) {
							try {
								await options.cache.delete(`consent:${consentCode}:bap_id`);
							} catch (e) {
								console.warn("⚠️ Could not delete consent KV entry:", e);
							}
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
			{
				matcher: (ctx) => ctx.path === "/oauth2/userinfo",
				handler: createAuthMiddleware(async (ctx) => {
					// Only proceed if we have getPool option
					if (!options?.getPool) {
						return;
					}

					// Get the access token from Authorization header
					const authHeader = ctx.headers?.get?.("authorization");
					if (!authHeader || !authHeader.startsWith("Bearer ")) {
						return;
					}

					const accessToken = authHeader.substring(7);

					// Look up the access token record to get selectedBapId
					const pool = options.getPool();
					try {
						const result = await pool.query(
							'SELECT "selectedBapId", "userId" FROM "oauthAccessToken" WHERE "accessToken" = $1 LIMIT 1',
							[accessToken],
						);

						if (result.rows.length === 0 || !result.rows[0].selectedBapId) {
							return; // No selected BAP ID, use primary (default behavior)
						}

						const selectedBapId = result.rows[0].selectedBapId;

						// Get BAP ID details from user_bap_ids table
						const bapResult = await pool.query(
							"SELECT bap_id, name FROM user_bap_ids WHERE bap_id = $1 LIMIT 1",
							[selectedBapId],
						);

						if (bapResult.rows.length === 0) {
							return; // Selected BAP ID not found, use primary
						}

						// Modify the response to use selected BAP ID instead of primary
						const responseBody = ctx.context.returned;
						if (responseBody && typeof responseBody === "object") {
							console.log(
								`✅ [OAuth Userinfo] Returning selected BAP ID: ${selectedBapId.substring(0, 15)}...`,
							);

							return {
								context: {
									...ctx,
									returned: {
										...responseBody,
										bap_id: bapResult.rows[0].bap_id,
										bap_name: bapResult.rows[0].name,
									},
								},
							};
						}
					} catch (error) {
						console.error(
							"❌ [OAuth Userinfo] Error retrieving selected BAP ID:",
							error,
						);
					} finally {
						if (pool && typeof pool.end === "function") {
							await pool.end();
						}
					}
				}),
			},
			{
				matcher: (ctx) => ctx.path === "/oauth2/consent",
				handler: createAuthMiddleware(async (ctx) => {
					console.log("🔵 [OAuth Consent Hook] Consent hook triggered");

					// Only proceed if we have the necessary options
					if (!(options?.getPool && options?.cache)) {
						console.warn(
							"⚠️ [OAuth Consent Hook] Missing getPool or cache options",
						);
						return;
					}

					const body = ctx.body as Record<string, unknown>;
					const consentCode = body.consent_code as string;
					const accept = body.accept as boolean;
					const clientId = body.client_id as string;

					console.log(
						`🔵 [OAuth Consent Hook] Body: accept=${accept}, consentCode=${consentCode ? `${consentCode.substring(0, 20)}...` : "undefined"}, clientId=${clientId ? `${clientId.substring(0, 20)}...` : "undefined"}`,
					);

					// Only store selectedBapId if consent was accepted
					if (!accept || !consentCode || !clientId) {
						console.warn(
							`⚠️ [OAuth Consent Hook] Skipping - accept=${accept}, consentCode=${!!consentCode}, clientId=${!!clientId}`,
						);
						return;
					}

					try {
						const pool = options.getPool();

						// Get session for userId
						const session = ctx.context.session;
						if (!session?.user?.id) {
							console.warn(
								"⚠️ [OAuth Consent Hook] No session found to link consent",
							);
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						// Retrieve selected BAP ID from cache/KV
						console.log(
							`🔵 [OAuth Consent Hook] Retrieving BAP ID from KV: consent:${consentCode}:bap_id`,
						);
						const selectedBapId = await options.cache.get<string>(
							`consent:${consentCode}:bap_id`,
						);

						console.log(
							`🔵 [OAuth Consent Hook] Retrieved BAP ID: ${selectedBapId || "null"}`,
						);

						if (!selectedBapId) {
							console.warn(
								`⚠️ [OAuth Consent Hook] No BAP ID selection found in KV for consent code: ${consentCode}`,
							);
							if (pool && typeof pool.end === "function") {
								await pool.end();
							}
							return;
						}

						// Wait a bit for Better Auth to create the consent record
						await new Promise((resolve) => setTimeout(resolve, 100));

						console.log(
							`🔵 [OAuth Consent Hook] Updating consent record: userId=${session.user.id.substring(0, 15)}..., clientId=${clientId.substring(0, 15)}..., bapId=${selectedBapId.substring(0, 15)}...`,
						);

						// Update the consent record with selectedBapId
						const result = await pool.query(
							'UPDATE "oauthConsent" SET "selectedBapId" = $1 WHERE "userId" = $2 AND "clientId" = $3 ORDER BY "createdAt" DESC LIMIT 1',
							[selectedBapId, session.user.id, clientId],
						);

						console.log(
							`🔵 [OAuth Consent Hook] UPDATE query result: rowCount=${result.rowCount}`,
						);

						console.log(
							`✅ [OAuth Consent Hook] Stored BAP ID in consent: user=${session.user.id.substring(0, 15)}... bap=${selectedBapId.substring(0, 15)}... client=${clientId.substring(0, 15)}...`,
						);

						if (pool && typeof pool.end === "function") {
							await pool.end();
						}
					} catch (error) {
						console.error(
							"❌ [OAuth Consent Hook] Error storing identity selection:",
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
					console.log(
						"🟢 [Sigma Plugin] BEFORE hook triggered for /oauth2/token",
					);
					const body = ctx.body as Record<string, unknown>;
					const grantType = body.grant_type as string;
					console.log(`🟢 [Sigma Plugin] Grant type: ${grantType}`);

					// Handle authorization_code grant type (exchange code for token)
					if (grantType === "authorization_code") {
						console.log(
							"🟢 [Sigma Plugin] Processing authorization_code grant",
						);
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
				if (!parsed?.pubkey) {
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
					} catch (error: unknown) {
						console.error("Error creating user:", error);

						// If duplicate key error, try to find the user again by pubkey
						if (
							error &&
							typeof error === "object" &&
							"code" in error &&
							error.code === "23505"
						) {
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
