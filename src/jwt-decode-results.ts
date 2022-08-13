export interface JwtHeader {
  alg: string;
  typ?: string;
}

export interface SimpleJwtPayload {
  iss?: string;
  aud?: string;
  sub?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  jti?: string;
}

/**
 * Successfully decoded JWT parameterized by a payload type.
 * @typeParam T the payload type constraint
 */
export interface DecodedJwt<T> {
  header: JwtHeader;
  payload: T;
  /** The raw original token. */
  raw: string;
}

/** Explanations for failure to decode a JWT. */
export enum JwtDecodeError {
  /** This JWT is completely mangled - it's either empty or doesn't have enough segments. */
  MangledJwt = "mangled JWT",
  /** There's a header, but it can't be base-64 decoded. */
  InvalidBase64Header = "invalid base64-encoded header",
  /** There's a payload, but it can't be base-64 decoded. */
  InvalidBase64Payload = "invalid base64-encoded payload",
  /** We can't parse the JSON for the header. */
  MalformedHeaderJSON = "can't parse header JSON",
  /** We can't parse the JSON for the payload. */
  MalformedPayloadJSON = "can't parse payload JSON",
  /** The header is valid JSON, but it's missing things. */
  InvalidHeaderObject = "invalid header - properties missing",
  /** The payload is valid JSON, but it's missing things. */
  InvalidPayloadObject = "invalid payload - properties missing"
}

/**
 * JWT decoding result parameterized by a payload type.
 * @typeParam T the payload type constraint
 */
export type JwtDecodeResult<T> = DecodedJwt<T> | JwtDecodeError;

export function isDecodedJwt<T>(result: JwtDecodeResult<T>): result is DecodedJwt<T> {
  return (result as DecodedJwt<T>).raw !== undefined;
}