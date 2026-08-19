# ADR 0003: Development infrastructure stays below $200/month

Status: accepted

## Decision

Use AKS Free management tier, two PAYG ARM64 system nodes, ACR Basic, Standard Load Balancer, Flux, and direct public ingress. Start manually and stop nightly. Do not provision NAT Gateway, Azure Front Door, a database, Redis, Key Vault, or paid telemetry in development.

## Rationale

AKS Automatic and Azure Front Door Premium consume most or all of the budget before worker compute. Scheduled PAYG nodes preserve flexibility and cost less than a reservation when the cluster is stopped for most nights and weekends.

## Consequences

This environment is intentionally unavailable while stopped and has no control-plane SLA. Budgets notify at $150, $180, and $195 but cannot enforce a hard cap. Operators must investigate the first alert rather than waiting for the final threshold.

