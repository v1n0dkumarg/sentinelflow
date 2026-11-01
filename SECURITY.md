# Security Policy

## Scope

SentinelFlow is a defensive local portfolio system using fictional events and mock response actions. Do not send real telemetry, credentials, or personal data to it.

## Reporting

Do not publish secrets or sensitive data in a public issue. Use GitHub private vulnerability reporting when available. Include the affected version, local reproduction steps, and impact.

## Deployment

The checked-in users and passwords are local examples. The app binds to loopback in Compose and uses HTTP Basic for local testing. Before any non-local deployment, replace demo users with OIDC-backed identity, require TLS, use managed secret storage, and review audit and network controls. No action connector may change external systems.
