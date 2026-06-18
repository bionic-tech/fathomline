# Generated API types

This directory holds the OpenAPI-generated TypeScript types, produced from the running api's
`/openapi.json` by:

```
npm run gen:api   # openapi-typescript http://localhost:8088/openapi.json -o src/api/generated/openapi.ts
```

CI regenerates these on every build so the typed client never drifts from the server contract
(API ADD §2/§9; spec risk: "OpenAPI-generated client drift"). Until generation runs, the
hand-written shapes in `../types.ts` are the compile-time contract. Do not edit generated
output by hand.
