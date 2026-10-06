# Explicit transport address family

The default STORMLAB_ADDRESS_FAMILY=system retains normal operating-system address selection. Set STORMLAB_ADDRESS_FAMILY=ipv4 explicitly in the operator process before starting the reviewed commands when the IPv6 route is failing:

    $env:STORMLAB_ADDRESS_FAMILY = 'ipv4'

The core HTTP client resolves the original allowlisted hostname with getaddrinfo(AF_INET), makes one connection attempt to its first returned IPv4 address, and uses the original hostname for TLS SNI/certificate validation and the HTTP Host header. It does not hardcode an address, edit DNS, change global Azure CLI settings, follow redirects, use proxies or retry a probe. Certificate verification is unchanged. Unknown mode values fail closed.

In IPv4 mode, lab_support.assert_owned performs its exact resource-group metadata GET through the existing Guard/HTTP/AzureCLI operator credential provider, preserving subscription, tenant, resource ID and lab-tag checks. It avoids az group show for that metadata request. Azure CLI still supplies operator account/token context; its own identity endpoints and the separate credential Graph/login request helper retain system routing. This option does not claim to change every outbound call in the process.

live_trial and storage_trial receipts record transport_address_family for the core HTTP path and credential_transport_address_family=system for that separate credential path. Raw probe starts/samples and linked summaries retain the core mode. Summary grouping separates modes and cross-mode baseline/post stitching is rejected. A storage series cannot resume under a changed mode. Earlier receipts without this field remain unrecorded; do not backfill a transport assertion without separate provenance.

Keep the mode fixed throughout a cohort. Removing the environment variable later restores the default for newly created clients/processes. Existing credential and ownership guards still apply; IPv4 selection is not a way around a failed certificate or authorization decision.

Probe metadata also captures a GUID-validated x-ms-correlation-request-id as correlation_id when supplied by Azure. It retains a valid client request ID only if one was already sent; it does not invent one. Matching event counts and overlapping times alone do not prove a one-to-one AzureActivity correlation.
