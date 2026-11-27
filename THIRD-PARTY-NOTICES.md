# Third-party acknowledgments and license inventory

Review date: 2026-11-27. Scope: the public RightsFrames-Termux source at commit `89c9b58e00aedb94da5ba8f60f75480c9ea7c26e`. This is a preliminary inventory, not an SBOM or a license clearance certificate. All upstream rights remain with their respective owners. The repository MIT license does not replace third-party terms. Verify exact distribution metadata, copyright notices, complete license text, modifications and bundled components before release.

## Python dependency inventory

Current upstream license declarations for the following projects were reviewed; pinned artifact license text and distribution obligations are still pending for every row. Other rows remain UNKNOWN. Platform markers are retained.

| Scope | Locked dependency | Upstream license (preliminary) | Source |
|---|---|---|---|
| runtime | `annotated-doc==0.0.5` | UNKNOWN | Pending |
| runtime | `annotated-types==0.8.0` | UNKNOWN | Pending |
| runtime | `anyio==4.15.1` | UNKNOWN | Pending |
| runtime | `cffi==2.1.1` | UNKNOWN | Pending |
| runtime | `click==8.5.0` | UNKNOWN | Pending |
| runtime | `cryptography==50.0.2` | Apache-2.0 OR BSD-3-Clause | [Upstream](https://github.com/pyca/cryptography/blob/main/LICENSE) |
| runtime | `fastapi==0.162.0` | MIT | [Upstream](https://github.com/fastapi/fastapi/blob/master/LICENSE) |
| runtime | `h11==0.16.0` | UNKNOWN | Pending |
| runtime | `idna==3.20` | UNKNOWN | Pending |
| runtime | `opentelemetry-api==1.45.2` | UNKNOWN | Pending |
| runtime | `pycparser==3.12` | UNKNOWN | Pending |
| runtime | `pydantic==2.14.4` | MIT | [Upstream](https://github.com/pydantic/pydantic/blob/main/LICENSE) |
| runtime | `pydantic-core==2.50.5` | MIT | [Upstream](https://github.com/pydantic/pydantic-core/blob/main/LICENSE) |
| runtime | `starlette==1.10.0` | BSD-3-Clause | [Upstream](https://github.com/Kludex/starlette/blob/main/pyproject.toml) |
| runtime | `typing-extensions==4.16.0` | UNKNOWN | Pending |
| runtime | `typing-inspection==0.4.4` | UNKNOWN | Pending |
| runtime | `uvicorn==0.54.0` | BSD-3-Clause | [Upstream](https://github.com/Kludex/uvicorn/blob/main/pyproject.toml) |
| test | `anyio==4.15.1 ; sys_platform != 'emscripten'` | UNKNOWN | Pending |
| test | `colorama==0.4.6 ; sys_platform == 'win32'` | UNKNOWN | Pending |
| test | `h11==0.16.0 ; sys_platform != 'emscripten'` | UNKNOWN | Pending |
| test | `httpcore2==2.16.0 ; sys_platform != 'emscripten'` | UNKNOWN | Pending |
| test | `httpx2==2.16.0` | UNKNOWN | Pending |
| test | `httpx2-jsfetch==1.0 ; sys_platform == 'emscripten'` | UNKNOWN | Pending |
| test | `idna==3.20` | UNKNOWN | Pending |
| test | `iniconfig==2.3.1` | UNKNOWN | Pending |
| test | `packaging==26.3` | UNKNOWN | Pending |
| test | `pluggy==1.7.0` | UNKNOWN | Pending |
| test | `pygments==2.21.0` | UNKNOWN | Pending |
| test | `pytest==9.2.0` | UNKNOWN | Pending |
| test | `truststore==0.10.5 ; sys_platform != 'emscripten'` | UNKNOWN | Pending |
| test | `typing-extensions==4.16.0 ; (python_full_version < '3.15' and sys_platform != 'emscripten') or (python_full_version < '3.13' and sys_platform == 'emscripten')` | UNKNOWN | Pending |

## Standards and project acknowledgments

The project documentation identifies RFC 9162 (Certificate Transparency, Merkle proofs), RFC 8032 (Ed25519), and NIST FIPS 204 (ML-DSA). Credit the standards authors, contributors and implementers; use the normative sources: https://www.rfc-editor.org/rfc/rfc9162.html ; https://www.rfc-editor.org/rfc/rfc8032.html ; https://csrc.nist.gov/pubs/fips/204/final . A reference to a standard does not imply endorsement, validation, certification or ownership of the standard.

The README discloses extensive AI-assisted development. Preserve human-authorship evidence, contributor records and relevant AI service terms. This is not a representation that any tool or contributor has transferred rights beyond documented terms.

## Release review still required

Capture resolved platform-specific packages and OS/base-image components, CI actions, Rust/JavaScript/native dependencies where present, optional dependencies, copied snippets, test vectors, generated assets, and full release contents. Record version, source URL, license expression, copyright, modified/bundled status and license-text location. Retain all applicable original notices; do not certify absence of copyleft or third-party source based on this list alone. Resolve every unknown or document a justified non-distribution decision before commercial clearance.
