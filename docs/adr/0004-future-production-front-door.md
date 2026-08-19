# ADR 0004: Azure Front Door is a future production migration

Status: deferred

## Future decision

Before a production launch, budget and design Azure Front Door Premium with managed WAF, an AKS private origin through Private Link, AKS Standard control-plane SLA, at least three worker nodes, staging, centralized monitoring, numerical SLOs, and disaster-recovery requirements.

## Development constraint

No Azure Front Door resource, feature flag, Bicep module, DNS dependency, or charge is permitted in the development deployment. The stable public interface remains `https://soffort.com/mcp`, allowing the future edge layer to be inserted without changing MCP tools or authentication semantics.

