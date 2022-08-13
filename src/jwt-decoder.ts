import { JwtDecodeResult, SimpleJwtPayload, JwtDecodeError, JwtHeader } from "./jwt-decode-results";

export class JwtDecoder {
  static simpleDecodeJwt(jwt: string) : JwtDecodeResult<SimpleJwtPayload> {
    return this.decodeJwt<SimpleJwtPayload>(jwt);
  }

  static decodeJwt<T>(jwt: string, requiredProperties: (keyof T)[] = []) : JwtDecodeResult<T> {
    const jwtComponents : string[] = jwt.split(".");
    
    if (jwtComponents.length < 2) {
      return JwtDecodeError.MangledJwt;
    }

    if (jwtComponents[0].length === 0) {
      return JwtDecodeError.InvalidBase64Header;
    }

    if (jwtComponents[1].length === 0) {
      return JwtDecodeError.InvalidBase64Payload;
    }

    let headerFromB64: string | undefined = undefined;
    let payloadFromB64: string | undefined = undefined;
    try {
      headerFromB64 = atob(jwtComponents[0]);
    } catch {
      return JwtDecodeError.InvalidBase64Header;
    }
    try {
      payloadFromB64 = atob(jwtComponents[1]);
    } catch {
      return JwtDecodeError.InvalidBase64Payload;
    }

    let header : JwtHeader | undefined = undefined;
    let payload : T | undefined = undefined;
    let headerFromJson : any = null;
    try {
      headerFromJson = JSON.parse(headerFromB64);
    } catch {
      return JwtDecodeError.MalformedHeaderJSON;
    }
    if (this.isJwtHeader(headerFromJson)) {
      header = headerFromJson;
    } else {
      return JwtDecodeError.InvalidHeaderObject;
    }

    let payloadFromJson : any = null;
    try {
      payloadFromJson = JSON.parse(payloadFromB64);
    } catch {
      return JwtDecodeError.MalformedPayloadJSON;
    }

    if ((!this.matchesInvalidPayloadTypes(payloadFromJson)) && this.isJwtPayload<T>(payloadFromJson, requiredProperties)) {
      payload = payloadFromJson;
    } else {
      return JwtDecodeError.InvalidPayloadObject;
    }

    return {
      header: header,
      payload: payload,
      raw: jwt
    };
  }

  private static isJwtHeader(val: any) : val is JwtHeader {
    return (val as JwtHeader).alg !== undefined
  }

  private static isJwtPayload<T>(val: any, requiredProperties: (keyof T)[]) : val is T {
    if (requiredProperties.length < 1) return true;
    return requiredProperties.reduce(
      (result, current) => result && (current in (val as T)),
      true
    );
  }

  private static matchesInvalidPayloadTypes(val: any) {
    if (typeof val === "string") {
      return true;
    }
    if (typeof val === "number") {
      return true;
    }
    if (val instanceof Array) {
      return true;
    }
    return false;
  }
}
