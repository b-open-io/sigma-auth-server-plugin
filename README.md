# @sigma-auth/server-plugin

Better Auth server plugin for Bitcoin signature-based authentication with Sigma Identity.

## Installation

```bash
npm install @sigma-auth/server-plugin
# or
bun add @sigma-auth/server-plugin
```

## What is Sigma Identity?

Sigma Identity (`auth.sigmaidentity.com`) is a **centralized OAuth provider** for Bitcoin-based authentication. This server plugin handles Bitcoin signature verification and OAuth token exchange for platforms integrating with Sigma.

## Features

- **Bitcoin signature authentication** - Verify Bitcoin signatures via `bitcoin-auth`
- **OAuth 2.0 integration** - Handle authorization code exchange with Bitcoin-based client auth
- **Pubkey-based user identification** - No passwords, users identified by Bitcoin public key
- **Optional BAP ID resolution** - Integrate with Bitcoin Attestation Protocol
- **Optional subscription tiers** - Track user subscription levels
- **Configurable dependencies** - Inject your own DB pool, cache, and BAP resolver

## Setup

### Basic Setup

```ts title="auth.ts"
import { betterAuth } from "better-auth";
import { sigma } from "@sigma-auth/server-plugin";

export const auth = betterAuth({
  database: {
    // your database configuration
  },
  plugins: [
    sigma(), // Basic setup with no optional features
  ],
});
```

### Advanced Setup (with BAP ID and Subscriptions)

```ts title="auth.ts"
import { betterAuth } from "better-auth";
import { sigma } from "@sigma-auth/server-plugin";
import { Pool } from "@neondatabase/serverless";
import { kv } from "@vercel/kv";
import { resolvePubkeyAndRegisterBAPId } from "./lib/bap/resolver";

export const auth = betterAuth({
  database: {
    // your database configuration
  },
  plugins: [
    sigma({
      // Enable subscription tier tracking
      enableSubscription: true,

      // Provide BAP ID resolver
      resolveBAPId: resolvePubkeyAndRegisterBAPId,

      // Provide database pool getter
      getPool: () => new Pool({
        connectionString: process.env.POSTGRES_URL,
      }),

      // Provide cache implementation (optional)
      cache: {
        get: async (key) => await kv.get(key),
        set: async (key, value) => await kv.set(key, value),
      },
    }),
  ],
});
```

## API Reference

### `sigma(options?)`

Creates the Sigma Auth server plugin for Better Auth.

**Options:**

```typescript
interface SigmaPluginOptions {
  /**
   * Enable subscription tier support
   * Adds subscriptionTier field to user and session
   * @default false
   */
  enableSubscription?: boolean;

  /**
   * Optional BAP (Bitcoin Attestation Protocol) ID resolver
   * Resolves a Bitcoin pubkey to a BAP ID and registers it
   */
  resolveBAPId?: (
    pool: any,
    userId: string,
    pubkey: string,
    register: boolean
  ) => Promise<string | null>;

  /**
   * Optional database pool getter
   * Returns a database connection pool for BAP ID resolution
   */
  getPool?: () => any;

  /**
   * Optional cache implementation for BAP ID caching
   * Should provide get/set methods for key-value storage
   */
  cache?: {
    get: <T = any>(key: string) => Promise<T | null>;
    set: (key: string, value: any) => Promise<void>;
  };
}
```

## Endpoints

The plugin provides these endpoints:

### `POST /api/auth/sign-in/sigma`

Authenticates a user via Bitcoin signature.

**Headers:**
- `X-Auth-Token` (required) - Bitcoin authentication token

**Returns:**
```json
{
  "token": "session-token",
  "user": {
    "id": "user-id",
    "pubkey": "bitcoin-pubkey",
    "name": "user-name"
  }
}
```

## OAuth 2.0 Integration

The plugin handles OAuth token exchange with Bitcoin-based client authentication via hooks on `/oauth2/token`.

**Client Authentication:**
- Clients authenticate using Bitcoin signatures (no client_id/client_secret)
- Platform pubkey is extracted from the `X-Auth-Token` signature
- Platform must be registered in `oauthApplication` table with pubkey as `clientId`

**Supported Grant Types:**
- `authorization_code` - Exchange authorization code for access token
- `refresh_token` - Refresh an existing access token

## Database Schema

The plugin extends Better Auth schema:

```typescript
user: {
  pubkey: string (required, unique)
  subscriptionTier?: string (optional, if enableSubscription: true)
}

session: {
  subscriptionTier?: string (optional, if enableSubscription: true)
}
```

Run migrations after adding the plugin:

```bash
npx @better-auth/cli migrate
```

## Client Integration

Use with [@sigma-auth/client-plugin](https://github.com/b-open-io/sigma-auth-client-plugin):

```ts
import { createAuthClient } from "better-auth/react";
import { sigmaClient } from "@sigma-auth/client-plugin";

export const authClient = createAuthClient({
  plugins: [sigmaClient()],
});

// Usage
authClient.signIn.sigma(); // Redirects to Sigma Identity OAuth flow
```

## Environment Variables

```bash
# Optional: Database connection for BAP ID resolution
POSTGRES_URL=postgresql://...

# Optional: Your environment-specific config
```

## Security

- ✅ Bitcoin signature verification via `bitcoin-auth`
- ✅ OAuth 2.0 authorization code flow with PKCE support
- ✅ Platform authentication via Bitcoin signatures (no shared secrets)
- ✅ User private keys never exposed to your platform

## Requirements

- **better-auth** ^1.3.34 (peer dependency)
- **@bsv/sdk** ^2.0.0 (peer dependency)
- **bitcoin-auth** ^1.0.0 (peer dependency)

## Related Packages

- [@sigma-auth/client-plugin](https://github.com/b-open-io/sigma-auth-client-plugin) - Client-side Better Auth plugin
- [Sigma Identity](https://auth.sigmaidentity.com) - Centralized Bitcoin OAuth provider
- [bitcoin-auth](https://github.com/b-open-io/bitcoin-auth) - Bitcoin authentication library

## License

MIT
