# RightsFrames external release verification

This procedure deliberately does not use the A17, Termux, the local RightsFrames runtime, local ledgers, or Charlie's local signing keys.

## Trust boundary

The verifier trusts only:

- the public Git repository and immutable Git object IDs
- GitHub Release metadata and release attestations
- GitHub Actions artifact attestations
- Sigstore/GitHub trusted roots used by GitHub CLI
- the public source tree at the exact release tag
- the verifier's own local cryptographic operations

The release artifact must be reproducible from the public source tree, and its SLSA provenance must be signed by the dedicated reusable workflow `slsa-build-l3.yml`.

## Online verification

From a clean machine with Git, GitHub CLI, Python 3, and sha256sum:

```bash
git clone https://github.com/cloydRightsFrames/RightsFrames-Termux.git
cd RightsFrames-Termux
git show v0.3.0:tools/verify_release_external.sh
bash tools/verify_release_external.sh v0.3.0
```

Replace the tag with the release being examined.

The verifier performs all of these checks:

1. GitHub release attestation verification.
2. Release asset download from GitHub.
3. SHA-256 verification against the published checksum file.
4. Immutable tag object and peeled commit verification.
5. Public source checkout at the exact tag target.
6. Manifest repository, tag, commit, tree, artifact, digest, and policy verification.
7. Exact byte-for-byte reproduction of the release tarball from the public source tree.
8. SLSA Provenance v1 attestation verification.
9. Exact signer workflow identity verification.
10. Rejection of self-hosted runners.
11. From v0.3.0: the release SBOM (`RightsFrames-Termux-<tag>.cdx.json`) matches the
    digest in the release manifest, lists exactly the packages, versions and SHA-256
    hashes locked in the tag's `core/requirements.txt` (checked by the tag's own
    `tools/rf_release_sbom.py`), and is byte-for-byte the predicate of a CycloneDX
    attestation signed by `provenance-gate.yml` for the release artifact. A release from
    v0.3.0 on without an SBOM fails verification.

## Release SBOM

Each release from v0.3.0 publishes a CycloneDX 1.6 SBOM of the hash-locked runtime
dependencies. It is reproducible: CI generates it twice and requires identical bytes;
the timestamp is the tagged commit's time and the serial number is derived from the
repository, commit and version. To check one by hand:

```bash
TAG=v0.3.0
gh release download "$TAG" -R cloydRightsFrames/RightsFrames-Termux \
  -p "RightsFrames-Termux-$TAG.tar.gz" -p "RightsFrames-Termux-$TAG.cdx.json"
tar -xzf "RightsFrames-Termux-$TAG.tar.gz"
python3 "RightsFrames-Termux-$TAG/tools/rf_release_sbom.py" verify \
  --sbom "RightsFrames-Termux-$TAG.cdx.json" \
  --requirements "RightsFrames-Termux-$TAG/core/requirements.txt" --version "${TAG#v}"
gh attestation verify "RightsFrames-Termux-$TAG.tar.gz" -R cloydRightsFrames/RightsFrames-Termux \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow cloydRightsFrames/RightsFrames-Termux/.github/workflows/provenance-gate.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
```

The SBOM can be imported into dependency-tracking tools (for example OWASP
Dependency-Track) to watch the release for newly published vulnerabilities.

## Offline attestation verification

GitHub CLI can also download the attestation bundle and trusted roots for offline verification:

```bash
gh attestation download ./RightsFrames-Termux-v0.3.0.tar.gz -R cloydRightsFrames/RightsFrames-Termux
gh attestation trusted-root > trusted_root.jsonl
gh attestation verify ./RightsFrames-Termux-v0.3.0.tar.gz   -R cloydRightsFrames/RightsFrames-Termux   --bundle sha256:<artifact-digest>.jsonl   --custom-trusted-root trusted_root.jsonl   --signer-workflow cloydRightsFrames/RightsFrames-Termux/.github/workflows/slsa-build-l3.yml
```

The trusted-root file should be obtained from a trusted online environment immediately before importing signed material into an offline environment.

## Security claim

The intended build claim is **SLSA v1.2 Build Level 3** for release artifacts produced by the hardened reusable builder. SLSA Build L3 requires a hosted hardened build platform with isolation between runs and protection of provenance-signing material from user-defined build steps.

This repository does not claim that SLSA Build L3 makes the source itself trustworthy, nor that it removes the need to assess GitHub or Sigstore. The purpose is to remove the A17/local runtime and local self-attestation from the release verification trust path.

## Stronger trust separation

For a verifier that also refuses to trust the repository owner as a unilateral authority, the next trust-boundary upgrade is to move `slsa-build-l3.yml` into a separately governed public repository and reference that workflow by immutable commit SHA. That makes the trusted builder identity independent of the RightsFrames source repository.
