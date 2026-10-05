# Artifact validation status

The local validation command is:

    python fixtures/validate_artifacts.py

On 2026-10-05 it passed the following offline checks:

- Eight tracked artifact JSON documents parsed.
- Fifteen synthetic AzureActivity cases matched their declared eligibility predicates, including five unique eligible provider event IDs after deduplication. The scheduled analytic ranks eligible signals and selects at most one automation candidate per evaluation; five eligible fixture IDs are not five expected alerts.
- The core planning matrix contains 12 cases / 13 action configurations / 39 minimum independent trials. Its empty result fields remain not_tested; it is not a ledger of live runs.
- The 66-case extended menu remains optional and separate from the core workload.
- CSV and JSON case IDs agreed. Key1 and key2 rotation each require three independent trials; other configurations require at least three.
- The native scheduled analytic defaulted to disabled, retained exact actor/group parameters and matched the tracked KQL body.
- Four workbook components referenced actual provider tables with explicit workspace and time-range parameters.

This record describes structural/reference-fixture validation, not execution of KQL on Kusto, ARM deployment validation, or an Azure Workbook import/render test. The reference predicate checks intended fixture outcomes but is not a substitute for running the actual KQL. Consult the root verification record for any subsequent service checks or cloud measurements.

The extended menu does not require 198 independent cloud mutations. Several credential observations can share one action trial; do not count a secondary observation as an independent response trial. Follow the core matrix for the initial study and the root verification record for completed checks.

No cloud resource was created, changed, queried or deleted by this validation. Primary-source documentation was read separately.
