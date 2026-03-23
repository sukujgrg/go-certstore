# Convergence Audit Prompt

```text
Run a 3-pass convergence audit on this repository. Use the current workspace state, but re-read `README.md` at the start of each pass and treat its scope, non-goals, and library/application boundary as the contract.

General rules for all passes:
- Audit the entire repo, not a subset.
- Stay within the scope/boundary defined in `README.md`.
- Fix concrete issues instead of only reporting them.
- Add or strengthen regression tests for every real correctness fix.
- Update docs/comments only when they are stale, misleading, or incomplete relative to actual behavior.
- Do not spend time on cosmetic-only edits.
- Run the relevant test suite after each pass that changes code/tests.
- Keep going through all 3 passes before stopping.
- In each pass, report only new findings from that pass, not a full replay of earlier ones.
- Treat credential/PIN handling as a correctness and safety concern: check whether secret material is unnecessarily copied, retained, logged, exposed through errors, or left unwiped where the library actually controls the buffer lifetime.
- Do not invent or claim high-assurance secret-memory guarantees beyond what Go, `string` conversions, cgo, and underlying dependencies actually allow. If the implementation cannot provide a strong guarantee, document the real limit precisely.

Pass 1: Fix Pass
- Focus on implementation correctness first.
- Audit for:
  - behavioral bugs
  - context/cancellation/lifecycle mistakes
  - resource leaks / close semantics
  - backend-selection / backend-resolution mistakes
  - incorrect error handling
  - missing edge-case handling
  - credential/PIN handling mistakes, including avoidable secret copies, missed buffer wiping, accidental retention, or exposure in logs/errors
- Fix every concrete implementation issue you find.
- Add or update regression tests for each fix.
- Run tests.

Pass 2: Adversarial Review Pass
- Assume Pass 1 missed bugs.
- Review the entire repo again from scratch as a skeptical code reviewer.
- Try to break assumptions in:
  - exported API semantics
  - nil/empty/error paths
  - cancellation timing
  - resource ownership and cleanup
  - multi-match selection/ranking logic
  - backend-specific divergence from generic API promises
  - tests that may pass without proving the intended behavior
  - credential/PIN handling under retries, callback reuse, later re-authentication, and failure paths
- Fix any newly found concrete correctness issue.
- Add regression tests for each new fix.
- Run tests again.

Pass 3: Docs and Contract Alignment Pass
- Compare implementation and tests against:
  - `README.md`
  - exported Go doc comments
  - examples
  - docs under `docs/`
  - inline code comments
- Find stale, misleading, or incomplete documentation/comments that would cause users or maintainers to misunderstand real behavior.
- Pay specific attention to credential/PIN handling docs:
  - whether buffers are wiped or not
  - whether secrets are copied internally
  - what guarantees the library does and does not make
- If docs imply behavior that is not implemented, either:
  - fix the implementation if that behavior is clearly intended and within README scope, or
  - correct the docs if the implementation is the intended behavior
- Run tests again if code/tests changed.

Final output requirements:
- Section 1: Pass 1 findings and fixes
- Section 2: Pass 2 findings and fixes
- Section 3: Pass 3 findings and fixes
- Section 4: Tests added/updated
- Section 5: Remaining risks or things you could not verify
- Section 6: Explicit statement on whether the repo is now aligned with `README.md`
- Section 7: A recommended git commit message for the full change set, and it must include a conventional change-kind prefix such as `fix:`, `refactor:`, `docs:`, `test:`, or `ci:`

Do not stop early after the first issue. Finish all 3 passes and only then conclude.
```
