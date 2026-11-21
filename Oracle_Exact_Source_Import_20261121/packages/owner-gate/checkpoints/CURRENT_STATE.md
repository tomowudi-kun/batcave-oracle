# Current state — 2026-11-20 EST

- **PRODUCTION_VERIFIED:** Oracle native Xubuntu worker supports typed inventory and deterministic build with server receipts; Cortana has a running `LOCAL SERVICE` lab reviewer; Ed25519 `LAB_ALLOW` and `DENY` signatures independently verified off-host.
- **LAB_PASS:** Oracle local `qwen2.5-coder:1.5b` generated Python code that passed eight tests. Hardened Oracle model-worker v0.3.1 is tested but staged. Owner-authenticated gate v0.2 source and synthetic signature tests pass; temporary schema runtime passed and rolled back.
- **STAGED:** This v0.2 package adds owner-authenticated lab enrollment and grant recording to the existing gate; no live code change.
- **BLOCKED:** Owner signed enrollment, independently reviewed gate release, guarded v0.3.1 deployment, live cloud→model→eight tests→one receipt, and next-ready chaining.
- **SECURITY:** All eight live change-gate rules remain shadow-only. The Cortana public key is LAB ONLY; no production authority. Do not substitute the HELD public-key intent for verified enrollment.
- **Critical hash distinction:** `4958...` is a fixed lab compatibility token; `4fd544...` pins the actual v0.3.1 archive for a later separate reviewed release.
- **Next eligible action:** independent approval of the exact existing-gate extension + owner signing client support. Do not repeat the earlier local model install, source snapshot capture, reviewer setup, or old schema tests absent new evidence.
