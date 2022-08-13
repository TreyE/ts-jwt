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

export interface DecodedJwt<T> {
  header: JwtHeader;
  payload: T;
  raw: string;
}

export enum JwtDecodeError {
  MangledJwt = "mangled JWT",
  InvalidBase64Header = "invalid base64-encoded header",
  InvalidBase64Payload = "invalid base64-encoded payload",
  MalformedHeaderJSON = "can't parse header JSON",
  MalformedPayloadJSON = "can't parse payload JSON",
  InvalidHeaderObject = "invalid header - properties missing",
  InvalidPayloadObject = "invalid payload - properties missing",
  UnknownError = "unknown error"
}

export type JwtDecodeResult<T> = DecodedJwt<T> | JwtDecodeError;