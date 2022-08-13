# @treye/ts-jwt

Decode and work with JWT in a type-safe way.

It is highly recommended you work with this package from TypeScript.

## Installation

This package runs on Node.js and is available as an NPM package.

```text
npm install @treye/ts-jwt
```

## Usage

A single class is exposed to decode JWTs: `JwtDecoder`.

The class offers two static methods:
1. `simpleDecodeJwt(jwt: string): JwtDecodeResult<SimpleJwtPayload>` - decode a JWT into a structure using a simplified, default payload type.
2. `decodeJwt<T>(jwt: string, requiredProperties?: (keyof T)[]): JwtDecodeResult<T>` - decode a JWT into a structure with a payload interface of your choosing.