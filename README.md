# MathWise DI² — Erdős 125 Global Multirow Coercivity Certificate

This repository preserves the version 1.1 fixed-instance certificate package for a specified Erdős Problem 125 setup. It is a mathematical proof and reproducibility record, not a complete solution to the general problem.

## Recorded certificate

The release records a unique target `c*` and the fixed-interval operator bound

```text
1/2 I <= W2(c*) <= 2 I
```

in the Loewner order on the stated interval `[0,H2]`. It also records finite-state Schur conditions, exact source-functional data, ranks and nullities, proof packets, and nonunique auxiliary Schur completions. The release notes classify version 1.1 as a packaging-only reproducibility repair and identify the successful clean-room decision as:

```text
A. CLEAN-ROOM GLOBAL CERTIFICATE FULLY REPRODUCED AFTER SOURCE REPAIR
```

The accompanying `pdf_validation_report.json` records **PASS** for rendering, embedded fonts, navigation, searchable text, pagination, and the stated visual inspection.

## Evidence and replay

Key artifacts include `Global_Multirow_Coercivity_Certificate.pdf`, `MANIFEST.json`, `REPRODUCE.txt`, `SCOPE_AND_LIMITATIONS.txt`, the proof/source ZIPs, clean-room audit ZIPs, `verify_global_certificate_v2.py`, and `SHA256SUMS.txt`. The manifest records release version `1.1`, embedded certificate version `1.0`, and SHA-256 identities for the package members.

## Scope and limitations

The certificate applies only to the uniquely certified target, fixed interval, target shifts, transition, and source operator stated in `SCOPE_AND_LIMITATIONS.txt`. It does not establish other intervals, shifts, coefficient vectors, architectures, residual problems, or a general Erdős 125 solution. The release claims SHA-256 integrity, not a digital signature or substantive truth from hashing alone.

The current repository checkout does not include four source ZIPs required by `REPRODUCE.txt` (`primal_schur_branch_packet.zip`, `primal_anchored_rotation_root_isolation.zip`, `active_lower15_schur_completion_packet.zip`, and `full_finite_state_primal_feasibility_packet.zip`), and the local environment lacks `mpmath`. Therefore a fresh end-to-end rerun was not performed here; the PASS status above is the package’s preserved release record, not a new independent execution.

## How to review

Read `SCOPE_AND_LIMITATIONS.txt` and `RELEASE_NOTES.txt` first, then `REPRODUCE.txt`, `MANIFEST.json`, the certificate PDF, and the verifier source. Run the verifier only after supplying every required source packet and the locked dependencies.

Publisher: Grounded DI LLC
