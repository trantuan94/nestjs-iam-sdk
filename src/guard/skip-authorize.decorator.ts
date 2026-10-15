import { SetMetadata } from '@nestjs/common';
import { SKIP_AUTHORIZE_METADATA } from './metadata';

/**
 * Exempts a route (or a whole controller) from the GLOBAL guard's
 * deny-by-default. The reason is required, and logged at boot with every
 * exempt route, so an exemption is always visible to whoever reads the logs.
 *
 * ```ts
 * @SkipAuthorize('liveness probe')
 * ```
 */
export const SkipAuthorize = (reason: string) => {
  if (typeof reason !== 'string' || reason.trim() === '') {
    throw new Error('@SkipAuthorize: a reason is required');
  }
  return SetMetadata(SKIP_AUTHORIZE_METADATA, reason);
};
