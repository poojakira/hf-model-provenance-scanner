# Remediation report

Branch codex/local-workbench-20261116. Local fixing source 2e77d42939cb09bd2e3a9f66c45e12d056550f35. Review baseline ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a.

- **HF-01** Both optional-core paths used a collection pipeline that hid pytest’s status. The patched step retains the ten-test minimum and returns failure on unsuccessful collection.
- **HF-02** Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record.

Read [documentation parity](DOCUMENTATION_PARITY.md) for the evidence pins. Historical poster figures and images retain their original date and provenance.
