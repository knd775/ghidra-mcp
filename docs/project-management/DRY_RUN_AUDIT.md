# Dry-run endpoint audit

Audited 2026-08-31 after `bsim_apply_matches` opened a Ghidra transaction around
its read-only preview and then collided with its background query worker.

## Shared dispatch behavior

`AnnotationScanner` now follows two rules for POST requests with
`dry_run=true`:

- If the endpoint declares `dry_run`, invoke it without opening a transaction.
  The endpoint owns its preview and must branch before its first mutation.
- If the endpoint does not declare `dry_run`, return `would_execute` without
  invoking it. This covers the synthetic flag added by the Python bridge and
  prevents filesystem, CLI, database, and server-admin writes that a Ghidra
  transaction cannot roll back.

`AnnotationScannerOfflineTest` checks the undeclared rule across the discovered
endpoint catalog and checks declared dispatch with dedicated fixtures. It also
checks that a failed declared preview opens no transaction and that an immediate
retry reaches the endpoint normally.

## Endpoints that declare `dry_run`

| Endpoint | Preview behavior checked | Result |
|---|---|---|
| `archive_ingest_function` | Builds the archive payload, returns before HTTP POST | Read-only |
| `archive_ingest_program` | Builds payloads and counts candidates, skips every HTTP POST | Read-only |
| `bsim_apply_matches` | Runs the BSim query and match filters, skips `setName` and every write transaction | Read-only |
| `build_manifest` | Resolves jobs and command lines, submits no builder jobs. `force=true` lists `would_replace` and still deletes nothing | Read-only |
| `build_reference` | Resolves command lines and expected artifact paths in the shared envelope (`status: would_execute`), submits no builder job. `force=true` lists `would_replace` and still deletes nothing | Read-only |
| `checkin_program` | Validates state, returns before save, close, or check-in | Read-only |
| `merge_program_documentation` | Counts merge candidates, never starts its target-program transaction | Read-only |
| `server/admin/terminate_all_checkouts` | Returns the proposed operation before recursive termination | Read-only |
| `server/admin/terminate_checkout` | Reads checkout state, returns before termination | Read-only |
| `server/version_control/add` | Validates file state, returns before `addToVersionControl` | Read-only |
| `server/version_control/checkin` | Validates checkout state, returns before `DomainFile.checkin` | Read-only |
| `server/version_control/checkout` | Validates file state, returns before `DomainFile.checkout` | Read-only |
| `server/version_control/undo_checkout` | Validates checkout state, returns before `DomainFile.undoCheckout` | Read-only |

The GUI and headless implementations of the server and version-control routes
share the same early-return behavior.

## Previously affected undeclared endpoints

`bsim_create_db`, `import_program`, and other POST endpoints without a declared
flag use the shared `would_execute` short circuit. Their handler is not invoked,
so a preview cannot create a database, write a project file, run a subprocess,
or perform another non-transactional side effect.
