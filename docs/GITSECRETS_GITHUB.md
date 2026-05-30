# Comparison of Github Secrets Scanner (Closed Source) vs Gitsecrets (Open Source)

See @docs/github_patterns_missing_from_gitleaks.csv for the full list of GitHub patterns missing from gitleaks. This was a comparison of rules (gitleaks.toml) vs supported matrix of GitHub: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns#supported-secrets

## Summary Stats

| Metric | Count |
|---|---|
| GitHub Secret Scanning patterns | 514 |
| Gitleaks rules | 222 |
| GitHub patterns **covered** by a gitleaks rule | ~281 (55%) |
| GitHub patterns **not covered** in gitleaks | ~233 (45%) |
| Gitleaks rules with **no GitHub equivalent** | 72 |

---

## Gitleaks-Only

These 72 rules detect things GitHub doesn't have specific patterns for:

`age-secret-key`, `algolia-api-key`, `artifactory-api-key`, `artifactory-reference-token`, `bittrex-access-key/secret-key`, `cisco-meraki-api-key`, `clickhouse-cloud-api-secret-key`, `codecov-access-token`, `coinbase-access-token`, `confluent-access/secret-token`, **`curl-auth-header`**, **`curl-auth-user`**, **`generic-api-key`**, `gitter-access-token`, `harness-api-key`, `infracost-api-token`, `intra42-client-secret`, **`jwt`**, **`jwt-base64`**, `kraken-access-token`, **`kubernetes-secret-yaml`**, `kucoin-access/secret`, `looker-client-id/secret`, `mattermost-access-token`, `netlify-access-token`, `new-relic-browser-api-token`, `new-relic-insert-key`, `new-relic-user-api-id/key`, `nytimes-access-token`, `okta-access-token`, `openshift-user-token`, **`pkcs12-file`**, `plaid-api-token/client-id/secret`, **`private-key`**, `privateai-api-token`, `rapidapi-access-token`, `scalingo-api-token`, `sendbird-access-id/token`, `settlemint-*`, `sidekiq-secret/url`, `snyk-api-token`, `sonar-api-token`, `squarespace-access-token`, `sumologic-access-id/token`, `travisci-access-token`, `twitch-api-token`, `twitter-*` (5 rules), **`vault-batch/service-token`**, `zendesk-secret-key`

---

## GitHub-Only (major providers NOT covered in gitleaks)

These **120+ providers** with **233 patterns** are in GitHub but missing from gitleaks:

- **AI/ML**: DeepSeek, Groq, Mistral AI, OpenRouter, Replicate, Pinecone, Weights & Biases, xAI, Hack Club AI, Langchain/LangSmith, VolcEngine Ark
- **Cloud/Infra**: Aiven, Docker (PAT/org tokens), Elastic, IBM Cloud IAM, Neon, Snowflake, Temporal, Tailscale, Vercel, Supabase, Localstack, Scalr, Naver Cloud
- **DevTools/CI**: Apify, Bitrise, Buildkite, CircleCI, Figma, Ionic
- **Payments/Fintech**: Cashfree, Checkout.com, Midtrans, Paddle, Rainforest Pay, Ramp
- **Monitoring/Observability**: LogicMonitor (bearer + LMv1), PagerDuty, PostHog, Samsara
- **Security Tools**: Aikido, GuardSquare, Proctorio, Onfido
- **Communication/Social**: Lark, Pinterest, Planning Center, Telnyx
- **Databases**: MongoDB Atlas, Datastax AstraCS, CockroachDB Cloud
- **E-commerce**: eBay (client IDs), Shopee
- **Misc notable**: Firebase Cloud Messaging, Salesforce, Oracle API Key, Palantir JWT, Tencent Cloud, Netflix NetKey

