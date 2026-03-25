import * as ed from '@noble/ed25519';
import {
  InterceptingCall,
  Interceptor,
  InterceptorOptions,
  Listener,
  Metadata,
  ServiceError,
} from '@grpc/grpc-js';

import {Keypair} from '@solana/web3.js';
import {NextCall} from '@grpc/grpc-js/build/src/client-interceptors';

import {
  AuthServiceClient,
  GenerateAuthChallengeRequest,
  GenerateAuthChallengeResponse,
  GenerateAuthTokensRequest,
  GenerateAuthTokensResponse,
  Role,
  Token,
} from '../../gen/block-engine/auth';
import {unixTimestampFromDate} from './utils';

// Export simplified error type for SDK users
export type AuthRefreshError = {
  reason: 'rate_limited' | 'auth_failed' | 'network_error' | 'invalid_response';
  message: string;
  retryAfter?: number;
};

// Intercepts requests and sets the auth header.
export const authInterceptor = (authProvider: AuthProvider): Interceptor => {
  return (opts: InterceptorOptions, nextCall: NextCall) => {
    return new InterceptingCall(nextCall(opts), {
      start: function (metadata: Metadata, listener: Listener, next) {
        authProvider.injectAccessToken(
          token => {
            metadata.set('authorization', `Bearer ${token.token}`);
            next(metadata, listener);
          },
          error => {
            console.error('injectAccessToken error in auth flow:', error);
            next(metadata, listener);
          }
        );
      },
    });
  };
};

// Represents server issued JWT tokens.
export class Jwt {
  readonly token: string;
  private readonly expiration: number;

  constructor(token: string, expiration: number) {
    this.token = token;
    this.expiration = expiration;
  }

  isExpired(): boolean {
    const now: number = unixTimestampFromDate(new Date());
    return this.expiration <= now;
  }
}

// Handles requesting and refreshing tokens, providing them via callbacks.
export class AuthProvider {
  private client: AuthServiceClient;
  private readonly authKeypair: Keypair;
  private accessToken: Jwt | undefined;
  private refreshToken: Jwt | undefined;

  constructor(client: AuthServiceClient, authKeypair: Keypair) {
    this.client = client;
    this.authKeypair = authKeypair;
  }

  async init() {
    // Get initial tokens
    const [accessToken, refreshToken] = await this.auth();
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;

    // Refresh tokens every 10 minutes
    setInterval(() => {
      this.auth()
        .then(([accessToken, refreshToken]) => {
          this.accessToken = accessToken;
          this.refreshToken = refreshToken;
        })
        .catch(err => {
          console.error('Error refreshing tokens:', err);
        });
    }, 10 * 60 * 1000);
  }

  public injectAccessToken(
    callback: (accessToken: Jwt) => void,
    errorCallback: (error: Error) => void
  ) {
    if (!this.accessToken) {
      errorCallback(new Error('No access token'));
      return;
    }

    if (this.accessToken?.isExpired()) {
      errorCallback(new Error('Access token expired'));
      return;
    }

    callback(this.accessToken);
    return;
  }

  // Run entire auth flow:
  // - fetch a server generated challenge
  // - sign the challenge and submit in exchange for an access and refresh token
  // - inject the tokens into the provided callback
  private auth(): Promise<[Jwt, Jwt]> {
    return new Promise<[Jwt, Jwt]>((resolve, reject) => {
      this.client.generateAuthChallenge(
        {
          role: Role.SEARCHER,
          pubkey: this.authKeypair.publicKey.toBytes(),
        } as GenerateAuthChallengeRequest,
        async (e: ServiceError | null, resp: GenerateAuthChallengeResponse) => {
          if (e) {
            reject(e);
            return;
          }

          // Append pubkey to ensure what we're signing is garbage.
          const challenge = `${this.authKeypair.publicKey.toString()}-${
            resp.challenge
          }`;
          const signedChallenge = await ed.sign(
            Buffer.from(challenge),
            // First 32 bytes is the private key, last 32 public key.
            this.authKeypair.secretKey.slice(0, 32)
          );

          this.client.generateAuthTokens(
            {
              challenge,
              clientPubkey: this.authKeypair.publicKey.toBytes(),
              signedChallenge,
            } as GenerateAuthTokensRequest,
            (e: ServiceError | null, resp: GenerateAuthTokensResponse) => {
              if (e) {
                reject(e);
                return;
              }

              if (!AuthProvider.isValidToken(resp.accessToken)) {
                reject(new Error('Received invalid access token from server'));
                return;
              }

              const accessToken = new Jwt(
                resp.accessToken?.value || '',
                unixTimestampFromDate(
                  resp.accessToken?.expiresAtUtc || new Date()
                )
              );

              if (!AuthProvider.isValidToken(resp.refreshToken)) {
                reject(new Error('Received invalid refresh token from server'));
                return;
              }

              const refreshToken = new Jwt(
                resp.refreshToken?.value || '',
                unixTimestampFromDate(
                  resp.refreshToken?.expiresAtUtc || new Date()
                )
              );

              resolve([accessToken, refreshToken]);
              return;
            }
          );
        }
      );
    });
  }

  private static isValidToken(token: Token | undefined) {
    if (!token) {
      return false;
    }

    if (!token.expiresAtUtc) {
      return false;
    }

    return true;
  }
}
