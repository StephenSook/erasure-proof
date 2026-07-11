# Erasure Proof Verifier (mobile)

An auditor's pocket verifier for erasure certificates. Import the signed proof the web app produces
(the `/proof` page's "Download the signed proof" button) and verify its ECDSA P-256 signature and
tamper-evidence **entirely on the device, with no server and no network**. Airplane mode and it
still works.

This is the mobile companion to the web console. It deliberately does the one thing that belongs on
a phone: an offline, trust-nobody check of a cryptographic erasure certificate.

## Why it is not a wrapper

The verification is real cryptography running on the device, not a WebView of the site:

- `@noble/curves` (audited, pure JavaScript) does the P-256 ECDSA verification. No native crypto
  module, and verification needs no randomness, so it runs in React Native / Hermes as-is.
- The signature is checked over the **exact signed bytes** (`proof_canonical`); the displayed facts
  are parsed from those same signed bytes, so what the verdict covers is what the screen shows.
- `lowS: false`, `format: 'der'`, externally computed SHA-256: byte-for-byte parity with the backend
  signer (pyca / AWS KMS) and the web WebCrypto verifier. The bundled `assets/demo-proof.json` was
  produced by the real `cryptod` signer, and `src/verify.test.ts` proves this verifier agrees with
  it (and rejects a tampered, reserialized, or wrong-key certificate).

## What is offline vs online

- **Offline (this app):** the ECDSA signature and tamper-evidence. This is the core "is this
  certificate authentic and unaltered" check.
- **Online (the web app):** the S3 Object Lock anchor and the full RFC 6962 inclusion/consistency
  proof, which need the transparency-log audit path from the server.

## Develop / run

```sh
cd mobile
npm install
npm run typecheck   # tsc --noEmit
npm test            # offline-verify parity + tamper/wrong-key/malformed cases

npm run ios         # iOS simulator (needs Xcode)
npm run android     # Android emulator or a connected device
```

## Android APK (installable, no store)

The truly downloadable artifact. With EAS:

```sh
npm install -g eas-cli
eas login
eas build --platform android --profile preview   # yields an installable .apk
```

Or a local debug build once the native project is generated (`npx expo prebuild`), via
`cd android && ./gradlew assembleDebug` (APK under `android/app/build/outputs/apk/debug/`).

## iOS (demo)

Run in the iOS **simulator** (free, via Xcode) for the demo video. On-device install or TestFlight
needs an Apple Developer account.
