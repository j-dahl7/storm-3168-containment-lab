# Artifact validation status

The local validation command is:

    python fixtures/validate_artifacts.py

On 2026-10-05 it passed the following offline checks:

- Seven JSON documents parsed.
- Fifteen synthetic AzureActivity cases matched their declared reference predicates, including six unique matching provider event IDs after deduplication.
- Sixty-six planned cases remained not_tested, with zero completed trials and no measured observations.
- CSV and JSON case IDs agreed; each case planned at least three independent action trials.
- The native scheduled analytic defaulted to disabled, retained exact actor/group parameters and matched the tracked KQL body.
- Four workbook components referenced actual provider tables with explicit workspace and time-range parameters.

This record describes structural/reference-fixture validation, not execution of KQL on Kusto, ARM deployment validation, or an Azure Workbook import/render test. The reference predicate checks intended fixture outcomes but is not a substitute for running the actual KQL. Consult the root verification record for any subsequent service checks or cloud measurements.

The matrix's minimum 198 case observations can share action trials across credential classes. This number is not a claim that 198 independent cloud mutations are required or have run.

No cloud resource was created, changed, queried or deleted by this validation. Primary-source documentation was read separately.
