# Project-wide adversarial repair report

Status: repairs complete on x86-64; native AArch64 execution remains external

Date: 2026-07-15

## Outcome

The project-wide adversarial findings were repaired without broadening either
package's public networking authority. The changes close five implementation
risks and two verification/documentation weaknesses:

1. Both release assemblers now require a clean Git worktree, fail closed when
   Git or Rust toolchain inspection fails, and record a verified `HEAD` rather
   than an unchecked or misleading commit string.
2. TPACKET_V3 block ownership now uses an acquire load before userspace reads a
   kernel-owned block and a release store before returning it to the kernel.
3. Fatal raw-reactor errors and panics now reject queued and registered native
   operations before completion sinks are cleared. A fault-injection regression
   proves a pending receive is settled with its original operation identity.
4. Phase 9 ring stress now uses the same owner-aware privileged wrapper as the
   other raw suites, so `sudo npm run test:phase9:stress` builds with the
   repository owner's Node/Rust toolchains and leaves no root-owned artifacts.
5. Passive observation IDs are deregistered when their session closes or
   readiness fails. Scanner/session close races use one ownership deletion so
   native observation closure occurs at most once.
6. The live route-context oracle accepts only a snapshot bracketed by an
   unchanged kernel neighbor count. It retries a changing startup fixture but
   still fails every stable mismatch.
7. Hardening and release-rehearsal workflows now execute the raw privileged,
   event-stress, and traceroute-stress suites; support and release documentation
   reflects the Phase 69 surface and exact-source staging rule.

## Verification

The following gates passed on the local x86-64 glibc Linux host:

- `npm run ci`, including formatting, ESLint, both TypeScript projects,
  workspace Clippy with warnings denied, all Rust and Node tests, npm audit, and
  both release-policy verifiers;
- `sudo npm run test:phase9:stress`, 256 iterations with descriptor count stable
  at 27;
- `sudo npm run test:privileged`, all 15 raw integration tests;
- `sudo npm run test:phase11:stress` and `sudo npm run test:phase15:stress`,
  both 256 iterations with stable descriptor counts;
- `sudo npm run test:phase24:namespace`, all 18 live scanner tests and all 3
  fault/fairness stress tests; and
- twelve consecutive `sudo npm run test:phase20:namespace` runs.

Both assemblers were also invoked from the intentionally dirty development tree
and rejected it with the new clean-worktree error before modifying staged
release output. A complete assembly requires a committed clean revision by
design.

No root-owned repository artifacts remained after the privileged matrix. Native
AArch64 execution, hosted sanitizer/fuzz schedules, and a clean-revision release
rehearsal remain CI/external gates and are not represented as locally verified.
