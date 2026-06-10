## Multi-Cloud Support

Cloudsplaining supports scanning IAM configurations across AWS, Azure, GCP, and OCI.

---

### AWS

**Required permissions:** `iam:GetAccountAuthorizationDetails` (included in `SecurityAudit` policy)

**Environment Variables**

```bash
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
```

**Step 1 — Download IAM authorization details:**

```bash
cloudsplaining download --output tmp/
```

**Step 2 — Scan:**

```bash
cloudsplaining scan \
  --input-file tmp/default.json \
  --skip-open-report \
  --flag-all-risky-actions \
  --flag-trust-policies \
  --verbose \
  --output tmp/
```

---

### Azure

**Step 1 — Create an App Registration:**

1. Go to **Azure Active Directory → App registrations → New registration**
2. Add the following API permissions:

   | Type        | Permission           |
   |-------------|----------------------|
   | Application | `Directory.Read.All` |
   | Delegated   | `Directory.Read.All` |

3. Assign the **Reader** role to the app on the target Subscription
4. Note the **Tenant ID**, **Client ID**, and **Subscription ID**
5. Create a **Client Secret** under *Certificates & secrets*

**Environment variables:**

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
```

**Step 2 — Collect snapshot:**

```bash
cloudsplaining collect-cloud -p azure \
  --subscription-id <subscription-id> \
  -o azure-snapshot.json
```

**Step 3 — Scan:**

```bash
cloudsplaining scan-cloud -p azure \
  -i azure-snapshot.json \
  -o json \
  --output-file az-report.json
```

---

### GCP

**Step 1 — Create a Service Account:**

1. Go to **IAM & Admin → Service Accounts → Create Service Account**
2. Grant the following roles on the target project:
   - `Security Reviewer`
   - `Viewer`
3. Create and download a JSON key for the service account

**Environment variable:**

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

**Step 2 — Collect snapshot:**

```bash
cloudsplaining collect-cloud -p gcp \
  --project-id <project-id> \
  -o gcp-snapshot.json
```

**Step 3 — Scan:**

```bash
cloudsplaining scan-cloud -p gcp \
  -i gcp-snapshot.json \
  -o json \
  --output-file gcp-report.json
```

---

### OCI

**Step 1 — Set up an audit user:**

1. Create a user and add it to an auditors group
2. Add the following policy to allow read-only inspection:

   ```
   Allow group <auditors> to inspect all-resources in tenancy
   ```

**Step 2 — Configure the OCI CLI:**

Create `~/.oci/config` with the following contents:

```ini
[DEFAULT]
tenancy=<tenancy-ocid>
user=<user-ocid>
fingerprint=<api-key-fingerprint>
region=<region>
key_file=<path-to-private-key>
```

**Environment Variables**

```bash
export OCI_CONFIG_FILE=<path-to-config-file>
```
or --config-file

**Step 3 — Collect snapshot:**

```bash
cloudsplaining collect-cloud -p oci \
  --config-file 'path' \
  --tenancy-id <tenancy-id> \
  -o oci-snapshot.json
```

**Step 4 — Scan:**

```bash
cloudsplaining scan-cloud -p oci \
  -i oci-snapshot.json \
  -o json \
  --output-file oci-report.json
```

---
