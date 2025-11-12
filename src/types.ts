/**
 * Type definitions for Sigma Auth server plugin
 */

export interface SigmaPluginConfig {
  /**
   * Optional BAP ID resolver function
   * Resolves on-chain Bitcoin Attestation Protocol identity from pubkey
   *
   * @param pubkey - Bitcoin public key
   * @returns BAP ID or null if not found
   */
  bapResolver?: (pubkey: string) => Promise<string | null>;

  /**
   * Optional subscription tier verifier
   * Checks user's subscription status (e.g., via NFT ownership)
   *
   * @param userId - Better Auth user ID
   * @returns Subscription tier string or null
   */
  subscriptionVerifier?: (userId: string) => Promise<string | null>;

  /**
   * Optional OAuth client verification
   * Verifies if a client (identified by pubkey) is registered
   *
   * @param pubkey - Client's Bitcoin public key
   * @returns true if client is registered, false otherwise
   */
  verifyOAuthClient?: (pubkey: string) => Promise<boolean>;

  /**
   * OAuth code storage interface
   * Defaults to in-memory storage (not suitable for production)
   * Use KV store (Vercel KV, Redis, etc.) in production
   */
  oauthCodeStorage?: OAuthCodeStorage;

  /**
   * Signature verification options
   */
  verification?: {
    /**
     * Maximum age of signature in minutes
     * @default 5
     */
    maxAge?: number;
  };
}

/**
 * OAuth authorization code data
 */
export interface OAuthCodeData {
  /** User's Bitcoin pubkey */
  pubkey: string;
  /** OAuth redirect URI */
  redirectUri: string;
  /** Better Auth user ID */
  userId: string;
  /** OAuth scope */
  scope: string;
  /** Session token */
  sessionToken: string;
  /** PKCE code challenge (optional) */
  codeChallenge?: string;
  /** PKCE code challenge method (optional) */
  codeChallengeMethod?: string;
}

/**
 * OAuth code storage interface
 * Implement this for your KV store
 */
export interface OAuthCodeStorage {
  /**
   * Store authorization code with expiration
   *
   * @param code - Authorization code
   * @param data - Code data
   * @param expiresIn - Expiration time in seconds
   */
  set(code: string, data: OAuthCodeData, expiresIn: number): Promise<void>;

  /**
   * Retrieve and delete authorization code
   *
   * @param code - Authorization code
   * @returns Code data or null if not found/expired
   */
  get(code: string): Promise<OAuthCodeData | null>;

  /**
   * Delete authorization code
   *
   * @param code - Authorization code
   */
  delete(code: string): Promise<void>;
}

/**
 * User with pubkey field
 */
export interface UserWithPubkey {
  id: string;
  pubkey: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  subscriptionTier?: string;
  createdAt: Date;
  updatedAt: Date;
}
