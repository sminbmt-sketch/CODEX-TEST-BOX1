# Tanium Integration Notes

This project uses Tanium in read-only mode during Phase 1.

## Gateway

The provided Tanium Gateway user guide identifies the external GraphQL endpoint as:

```text
https://<server>/plugin/products/gateway/graphql
```

The application builds this URL from:

- `TANIUM_BASE_URL`
- `TANIUM_GATEWAY_PATH`

## Authentication

The app expects an API token from an environment variable:

```text
TANIUM_API_TOKEN
```

Do not commit real tokens. Use `.env` on the deployment server and keep it out of Git.

## Phase 1 Allowed Operations

- Test Gateway connectivity.
- Query current user context.
- Query endpoint inventory using documented Gateway GraphQL examples.
- Normalize endpoint attributes for vulnerability impact matching.

## Phase 1 Blocked Operations

- Deploy actions.
- Approve saved actions.
- Create or modify packages/sensors.
- Run Direct Connect remediation.
- Quarantine or control endpoints.

Those operations require RBAC separation, approval workflow, dry-run support, and audit logs before implementation.
