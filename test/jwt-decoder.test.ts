import { JwtDecoder, JwtDecodeError, DecodedJwt, SimpleJwtPayload, isDecodedJwt } from "../src/index"

test('with an unparseable token (no dots)', () => {
  expect(JwtDecoder.simpleDecodeJwt("")).toBe(JwtDecodeError.MangledJwt);
});

test('with bogus base64 header', () => {
  expect(JwtDecoder.simpleDecodeJwt("'.A")).toBe(JwtDecodeError.InvalidBase64Header);
});

test('with bogus base64 payload', () => {
  expect(JwtDecoder.simpleDecodeJwt("AAA.';")).toBe(JwtDecodeError.InvalidBase64Payload);
});

test('with malformed header JSON', () => {
  expect(JwtDecoder.simpleDecodeJwt("AAA.AAA")).toBe(JwtDecodeError.MalformedHeaderJSON);
});

test('with invalid header contents', () => {
  const headerJson = btoa(JSON.stringify({}));
  expect(JwtDecoder.simpleDecodeJwt(`${headerJson}.AAA`)).toBe(JwtDecodeError.InvalidHeaderObject);
});

test('with invalid payload contents', () => {
  const headerJson = btoa(JSON.stringify({alg: "RS256"}));
  const payloadStringJson = btoa(JSON.stringify(""));
  const payloadNumberJson = btoa(JSON.stringify(6));
  const payloadArrayJson = btoa(JSON.stringify([]));
  const payloadObjectJson = btoa(JSON.stringify({}));
  expect(JwtDecoder.simpleDecodeJwt(`${headerJson}.${payloadStringJson}`)).toBe(JwtDecodeError.InvalidPayloadObject);
  expect(JwtDecoder.simpleDecodeJwt(`${headerJson}.${payloadNumberJson}`)).toBe(JwtDecodeError.InvalidPayloadObject);
  expect(JwtDecoder.simpleDecodeJwt(`${headerJson}.${payloadArrayJson}`)).toBe(JwtDecodeError.InvalidPayloadObject);
});

test('with valid simple payload contents', () => {
  const headerJson = btoa(JSON.stringify({alg: "RS256"}));
  const payloadJson = btoa(JSON.stringify({}));
  const decodeResult = JwtDecoder.decodeJwt<ConstrainedPayloadExample>(`${headerJson}.${payloadJson}`);
  expect(decodeResult).toStrictEqual<DecodedJwt<SimpleJwtPayload>>({"header": {"alg": "RS256"}, "payload": {}, "raw": "eyJhbGciOiJSUzI1NiJ9.e30="});
});

interface ConstrainedPayloadExample {
  item: string;
}

test('with invalid constrained payload contents', () => {
  const headerJson = btoa(JSON.stringify({alg: "RS256"}));
  const payloadJson = btoa(JSON.stringify({}));
  const decodeResult = JwtDecoder.decodeJwt<ConstrainedPayloadExample>(`${headerJson}.${payloadJson}`, ['item']);
  expect(isDecodedJwt(decodeResult)).toBe(false);
  expect(decodeResult).toBe(JwtDecodeError.InvalidPayloadObject);
});

test('with valid constrained payload contents', () => {
  const headerJson = btoa(JSON.stringify({alg: "RS256"}));
  const payloadJson = btoa(JSON.stringify({item: "hi"}));
  const decodeResult = JwtDecoder.decodeJwt<ConstrainedPayloadExample>(`${headerJson}.${payloadJson}`, ['item']);
  expect(isDecodedJwt(decodeResult)).toBe(true);
  expect(decodeResult).toStrictEqual<DecodedJwt<ConstrainedPayloadExample>>({"header": {"alg": "RS256"}, "payload": {"item": "hi"}, "raw": "eyJhbGciOiJSUzI1NiJ9.eyJpdGVtIjoiaGkifQ=="});
});