# Release Signing & Auto-Update — Runbook

This covers the two distribution-trust items that can't be completed in code alone
because they need paid certificates, Apple/Microsoft accounts, and CI secrets:

- **1.1 Code signing / notarization** (Windows + macOS)
- **3.1 Auto-update** (gated on signing)

> **Why this matters.** `checksums.txt` proves a download wasn't *corrupted in
> transit* — it is **integrity, not authenticity**. It's served from the same host
> as the binary, so a compromised release replaces both. Only a signature from a
> key the OS trusts proves the binary is genuinely from you. Until signing is in
> place, don't describe checksums as proof of authenticity.

The PyInstaller spec is already wired for this: macOS signing turns on
automatically when `GULLWING_CODESIGN_IDENTITY` / `GULLWING_ENTITLEMENTS` are set
in the build environment, and `packaging/entitlements.plist` is a ready-to-use
hardened-runtime entitlements file. Unset = unsigned build, unchanged.

---

## Windows — Azure Trusted Signing

Cheapest credible path (~$10/mo); EU/individual developers are eligible. Signs
without you holding a private key (the cert lives in Azure).

1. Create an **Azure Trusted Signing** account + certificate profile; verify identity.
2. Store as GitHub Actions secrets: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
   `AZURE_CLIENT_SECRET`, `AZURE_CODE_SIGNING_ACCOUNT`, `AZURE_CERT_PROFILE`.
3. In `build-release.yml`, after the Windows build, sign the produced `Gullwing.exe`:
   ```yaml
   - name: Sign Windows binary
     uses: azure/trusted-signing-action@v0
     with:
       azure-tenant-id:     ${{ secrets.AZURE_TENANT_ID }}
       azure-client-id:     ${{ secrets.AZURE_CLIENT_ID }}
       azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
       endpoint:            https://eus.codesigning.azure.net/
       trusted-signing-account-name: ${{ secrets.AZURE_CODE_SIGNING_ACCOUNT }}
       certificate-profile-name:     ${{ secrets.AZURE_CERT_PROFILE }}
       files-folder:        dist
       files-folder-filter: exe
   ```
4. Verify: `signtool verify /pa /v dist\Gullwing.exe`.

SmartScreen reputation still builds over downloads/time even when signed, but the
"unknown publisher" block disappears immediately.

---

## macOS — Developer ID + notarytool

Requires a paid **Apple Developer Program** membership ($99/yr).

1. Create a **Developer ID Application** certificate; export the identity to the
   build machine's keychain (or import via CI from a base64 secret).
2. Set in the signing job:
   ```bash
   export GULLWING_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
   export GULLWING_ENTITLEMENTS="packaging/entitlements.plist"
   ```
   The spec passes these straight to PyInstaller's `codesign_identity` /
   `entitlements_file`, signing with the hardened runtime.
3. Notarize and staple the built app:
   ```bash
   ditto -c -k --keepParent "dist/Gullwing.app" Gullwing.zip
   xcrun notarytool submit Gullwing.zip \
     --apple-id "$APPLE_ID" --team-id "$TEAM_ID" \
     --password "$APP_SPECIFIC_PASSWORD" --wait
   xcrun stapler staple "dist/Gullwing.app"
   ```
4. Verify: `spctl -a -vvv -t install dist/Gullwing.app` → "accepted, source=Notarized".

**Gotchas (the PyInstaller + numpy ones):**
- Hardened runtime crashes without the entitlements in `entitlements.plist`
  (JIT / unsigned-executable-memory / dyld env / library-validation).
- numpy/pygame ship nested `.dylib`/`.so` that must each be signed — PyInstaller
  signs them when `codesign_identity` is set, but a stray unsigned bundled binary
  fails notarization. Read the notarization log (`notarytool log <id>`) for the
  exact offender.
- Sign **after** PyInstaller assembles the bundle; re-signing a stapled app breaks
  the staple.

---

## 3.1 Auto-update (do this *after* signing)

Secure auto-update depends on signature trust — ship it only once 1.1 is done,
or you've built an update channel that can push an unverified binary to every
installed copy.

**Recommended:** [`tufup`](https://github.com/dennisvang/tufup) — a maintained
TUF (The Update Framework) implementation for frozen Python apps. (PyUpdater is
archived; don't use it.)

Outline:
1. Generate TUF roles/keys offline; keep the **root key offline**, sign the
   targets/snapshot/timestamp roles in CI.
2. Publish update archives + TUF metadata to a static host (the GitHub Releases
   bucket works as the target store).
3. Bundle the `tufup` client + the trusted root metadata in the app; on launch
   (or on a "Check for updates" button) it verifies signatures before applying.
4. Because every update is TUF-signed, a compromised host can't push a malicious
   update — which is exactly why this must follow code signing, not precede it.

Until this lands, the honest line for users is: "Update by downloading the latest
signed release from GitHub." Security fixes (e.g. the v1.1.2 injection fix) reach
users only when they re-download — call that out in release notes.
