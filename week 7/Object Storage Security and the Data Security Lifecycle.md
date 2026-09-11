# Object Storage Security and the Data Security Lifecycle

**Lab Report — IKB42603 Cloud Computing Security Essentials**

**Course:** IKB42603 Cloud Computing Security Essentials
**Lab:** Lab 6 — Object Storage Security & the Data Security Lifecycle (Weeks 11–12)
**CLO Mapping:** CLO2 — Construct secure cloud operations that safeguard data confidentiality and integrity (VBE3)
**CSA CCSK v5 Domains:** Domain 5 (Data Security) · Domain 4 (Organisation Management) · Domain 9 (Application Security — resource policy)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Environment Setup](#2-environment-setup)
3. [Session A (Week 11) — Object Storage & the Exposure Problem](#3-session-a-week-11--object-storage--the-exposure-problem)
   - [Task 1 — Classify the Data Before You Store It](#task-1--classify-the-data-before-you-store-it)
   - [Task 2 — Reproduce the Archetypal Breach](#task-2--reproduce-the-archetypal-breach)
   - [Task 3 — Remediate with Block Public Access](#task-3--remediate-with-block-public-access)
   - [Task 4 — Identity Policy vs Resource Policy](#task-4--identity-policy-vs-resource-policy)
4. [Session B (Week 12) — Protecting, Retaining and Retiring Data](#4-session-b-week-12--protecting-retaining-and-retiring-data)
   - [Task 5 — Default Encryption at Rest (SSE-KMS)](#task-5--default-encryption-at-rest-sse-kms)
   - [Task 6 — Delegated Access and the Condition-Key Trap](#task-6--delegated-access-and-the-condition-key-trap)
   - [Task 7 — Versioning, Delete Markers & Data Remanence](#task-7--versioning-delete-markers--data-remanence)
   - [Task 8 — Lifecycle Rules & Cryptographic Erasure](#task-8--lifecycle-rules--cryptographic-erasure)
5. [Data Classification Table](#6-data-classification-table)
6. [Short-Answer Questions](#7-short-answer-questions)
7. [Verification Command Output](#8-verification-command-output)
8. [Security Best-Practices Checklist](#9-security-best-practices-checklist)
9. [Reflection & Lessons Learned](#11-reflection--lessons-learned)
10. [Lab 2.1]()
11. [Lab 5.1]()

---

## 1. Executive Summary

This lab traced the full data security lifecycle of object storage on Amazon S3 (emulated via LocalStack). Session A addressed **who can reach the data** — data classification, the archetypal public-bucket breach, Block Public Access guardrails, and the interaction between identity-based and resource-based policies. Session B addressed **what state the data is in** — default SSE-KMS encryption, presigned URLs and the `aws:SecureTransport` condition-key trap, versioning and object-level data remanence, and cryptographic erasure through KMS key deletion.

The key finding is that object storage security is governed by **policy precedence** (explicit Deny > Allow > implicit default Deny), and that **preventative guardrails** (Block Public Access, bucket default encryption) are more reliable than detective controls. The lab also demonstrated that `delete-object` does **not** destroy data when versioning is enabled, and that cryptographic erasure via KMS key destruction provides stronger, provable deletion assurance than overwriting.

---

## 2. Environment Setup

### 2.1 One-Time Environment Setup

Start a clean, activated LocalStack instance and point the CLI at it. `ENFORCE_IAM=1` asks LocalStack to actually evaluate IAM policies rather than allowing everything — this is required for Task 4.

```bash
# Start clean
docker rm -f localstack 2>/dev/null

docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest
```
<img width="541" height="138" alt="image" src="https://github.com/user-attachments/assets/4911f5f3-9168-4de9-a462-4148e6157aa6" />
<img width="840" height="169" alt="image" src="https://github.com/user-attachments/assets/209eec1d-d099-47c5-b55e-6c5e003da72c" />

### 2.2 Point the CLI at LocalStack

```bash
export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
aws $EP sts get-caller-identity
```

**output:**
<img width="839" height="333" alt="image" src="https://github.com/user-attachments/assets/62c2875c-d8e8-40e1-9272-7d96f5fae118" />


> **Note:** Record the account number `000000000000` — this is needed for the ARNs written in Task 4.

### 2.3 Create the Bucket

```bash
export BUCKET="mii-patient-records-7615"
aws $EP s3api create-bucket --bucket $BUCKET
```

**output:**
<img width="675" height="123" alt="image" src="https://github.com/user-attachments/assets/8fbc9d10-c10e-4990-b002-46aa09f8762c" />


---

## 3. Session A (Week 11) — Object Storage & the Exposure Problem

> **Focus:** Who can reach the data. Every task in Session A corresponds to a control that, when missing, has produced a headline breach.

---

### Task 1 — Classify the Data Before You Store It

**Objective:** Create a bucket for a hospital records system and store three objects of different sensitivity, tagging each with its classification.

#### Step 1.1 — Create the three objects

```bash
echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt
```

#### Step 1.2 — Upload each object with a classification tag

```bash
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'
```

#### Step 1.3 — List the objects

```bash
aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key,Size]' --output table
```

#### Step 1.4 — Verify the confidential tag

```bash
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

**Output:**

<img width="974" height="465" alt="image" src="https://github.com/user-attachments/assets/f7b173d2-d1fb-494e-8981-6657159144f5" />
<img width="1134" height="921" alt="image" src="https://github.com/user-attachments/assets/b52a0042-282b-4644-a8d4-af73be074f64" />

---

### Task 2 — Reproduce the Archetypal Breach

**Objective:** Deliberately build a resource policy with `"Principal": "*"`, then read the confidential record with no credentials at all.

#### Step 2.1 — Create the public-read policy

```bash
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadEverything",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/*"
    }
  ]
}
JSON
```

#### Step 2.2 — Apply the policy

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

<img width="753" height="796" alt="image" src="https://github.com/user-attachments/assets/99a49ae6-3c30-4ccf-a1c9-d7fc988a73e5" />

#### Step 2.3 — The attacker's view: no AWS credentials, no CLI, just a URL

```bash
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt

cat leaked.txt
```

**Output:**
<img width="803" height="226" alt="image" src="https://github.com/user-attachments/assets/d85e905b-08c5-44d5-9a0a-3e45a133e56e" />


> **Caution:** HTTP 200 and the patient record printed in the terminal is the **whole breach**. There was no exploit, no malware and no vulnerability — only a policy that said `Principal: "*"`.

**Answer to "which single word caused the exposure?"**

The single element is the **asterisk `*`** in the `"Principal"` field. It grants the `s3:GetObject` permission to **everyone** (anonymous and authenticated users worldwide), turning the bucket into a public data source.

---

### Task 3 — Remediate with Block Public Access

**Objective:** Remove the bad policy, apply Block Public Access as a preventative guardrail, and attempt to re-introduce the public policy.

#### Step 3.1 — Remove the offending policy

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Step 3.2 — Apply the account-level guardrail to the bucket

```bash
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

#### Step 3.3 — Verify the guardrail

```bash
aws $EP s3api get-public-access-block --bucket $BUCKET
```

#### Step 3.4 — Try to re-introduce the public policy

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
```

> **Verify or explain:** LocalStack stores the Block Public Access configuration faithfully but does not always enforce it, so step 3.4 may succeed and the anonymous read may still return HTTP 200. If so, capture the `get-public-access-block` output as your evidence.

#### Step 3.5 — Re-test the anonymous read

```bash
curl -s -o /dev/null -w 'anonymous read after BPA: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

**On real AWS:** HTTP 403 (Access Denied). **On LocalStack:** may still return HTTP 200.

#### Evidence
<img width="753" height="796" alt="image" src="https://github.com/user-attachments/assets/638751e6-85a9-4275-86a3-cbcfae765523" />
<img width="803" height="226" alt="image" src="https://github.com/user-attachments/assets/889af6fa-a1fa-48c3-a311-bcc60be330d7" />

**Report answers:**

**(a) Which of the four flags would have rejected the policy on real AWS?**

`BlockPublicPolicy` — this flag rejects any bucket policy that grants public access (i.e., that includes `"Principal": "*"` without a restrictive condition). It is the direct preventative control against the Task 2 breach.

**(b) Why is a preventative guardrail stronger than a detective control that merely reports the bucket as public?**

A **detective control** (e.g., AWS Config rule, Security Hub finding, Trusted Advisor check) only *observes* and *reports* that a bucket is public — it does nothing to stop the exposure. A **preventative guardrail** such as Block Public Access **refuses the API call** that would make the bucket public in the first place. In an organisation with many engineers, a detective control depends on someone noticing and acting on the alert before an attacker finds the bucket; a preventative control removes the possibility entirely. This is the difference between locking the door and installing a camera that films the burglary.

---

### Task 4 — Identity Policy vs Resource Policy

**Objective:** Prove that when an identity policy and a resource policy disagree, an **explicit Deny always wins**.

#### Step 4.1 — Create the DataAnalyst IAM user

```bash
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json << 'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "*"
    }
  ]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json
```

#### Step 4.2 — Create access keys and configure a named profile

```bash
aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
```

```bash
# Copy the two values into these variables — keep the quotes, no angle brackets.
ANALYST_KEY_ID='PASTE_KEY_ID_HERE'
ANALYST_SECRET='PASTE_SECRET_HERE'

aws configure --profile analyst set aws_access_key_id "$ANALYST_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "$ANALYST_SECRET"
aws configure --profile analyst set region us-east-1
```

#### Step 4.3 — Create the conflicting bucket policy

```bash
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json
```

#### Step 4.4 — Test the internal object (should SUCCEED)

```bash
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt \
  && echo "internal: ALLOWED"
```

**Expected output:**

```
internal: ALLOWED
```

#### Step 4.5 — Test the confidential object (should FAIL)

```bash
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-conf.txt \
  || echo "confidential: DENIED"
```

#### Evidence

<img width="865" height="850" alt="image" src="https://github.com/user-attachments/assets/f2e536ab-13b5-4627-9166-208a475ab207" />
<img width="951" height="884" alt="image" src="https://github.com/user-attachments/assets/b8902b34-1e98-4490-9460-e1c6117ac302" />
<img width="701" height="625" alt="image" src="https://github.com/user-attachments/assets/ce992f89-21c7-4763-acac-799af88d2085" />

> **Verify or explain:** If LocalStack was not started with `ENFORCE_IAM=1`, both calls will succeed. Restart the container with the flag and retry. If it still does not deny, record both policy documents as evidence and write out the evaluation logic yourself: **default deny → any explicit Deny → any explicit Allow**. State which statement decides each of the two requests.

**Evaluation logic:**

| Request | Identity Policy | Resource Policy | Decision |
|---|---|---|---|
| `internal/roster.txt` | Allow `s3:GetObject` on `*` | Allow `s3:GetObject` on `internal/*` | **ALLOWED** — both policies allow |
| `confidential/record.txt` | Allow `s3:GetObject` on `*` | Explicit **Deny** `s3:*` on `confidential/*` | **DENIED** — explicit Deny overrides Allow |

> **Caution:** Remove this policy before Session B:
> ```bash
> aws $EP s3api delete-bucket-policy --bucket $BUCKET
> ```
> A Deny statement scoped to `s3:*` can lock **you** out as well if the principal ARN does not match exactly what you expected — which is itself one of the most common resource-policy incidents in production.

> **Note:** End of Session A. Keep your bucket, `$BUCKET` value, and all outputs — Session B builds directly on them.

---

## 4. Session B (Week 12) — Protecting, Retaining and Retiring Data

> **Focus:** What state the data is in — encrypted, versioned, retained, or provably destroyed.

---

### Task 5 — Default Encryption at Rest (SSE-KMS)

**Objective:** Make encryption a property of the bucket, so every object is encrypted whether or not the developer who uploads it remembers to ask.

#### Step 5.1 — Create a dedicated KMS key

```bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID
```

**Output:**

```
71c6076a-f1eb-4a49-b198-26b10660c9d8
```

#### Step 5.2 — Create the bucket encryption configuration

```bash
cat > encryption.json <<JSON
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "$KEY_ID"
      },
      "BucketKeyEnabled": true
    }
  ]
}
JSON
```

#### Step 5.3 — Apply and verify the encryption configuration

```bash
aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json

aws $EP s3api get-bucket-encryption --bucket $BUCKET
```

#### Step 5.4 — Upload with NO encryption flags at all

```bash
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt
```

#### Step 5.5 — Verify the object is encrypted with the KMS key

```bash
aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption, SSEKMSKeyId, BucketKeyEnabled]' --output text
```

#### Evidence
<img width="966" height="703" alt="image" src="https://github.com/user-attachments/assets/23f13eb1-a0fb-4af6-979d-6eaf313bc45b" />

> **Key insight:** The upload succeeded **without any encryption flags**. The bucket applied the KMS key automatically. This is the difference between a control that depends on developer discipline and a control that is a property of the bucket itself.

---

### Task 6 — Delegated Access and the Condition-Key Trap

**Objective:** Issue a time-bounded presigned URL, test its expiry, then apply the `aws:SecureTransport` policy and observe the lockout.

#### Step 6.1 — Generate a presigned URL (60-second expiry)

```bash
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
```
<img width="972" height="208" alt="image" src="https://github.com/user-attachments/assets/9bce2cbe-b5cf-4904-bee3-1360664d02ab" />


#### Step 6.2 — Access the URL before expiry

```bash
URL='http://localhost:4566/mii-patient-records-7615/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260910%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260910T215520Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=96261de5f4edff290560bedeebacabe551d093619b70201d65411eaf92c1afa2'

curl -s -w ' <- HTTP %{http_code}\n' "$URL"
```

#### Step 6.3 — Wait for expiry and retry

```bash
sleep 65

curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

<img width="972" height="449" alt="image" src="https://github.com/user-attachments/assets/033ad0da-6de5-40fe-b4f7-2fd601d1a39b" />

#### Step 6.4 — The condition-key trap

```bash
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

# Any ordinary call — expect it to be refused
aws $EP s3api list-objects-v2 --bucket $BUCKET

# Recover before continuing
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

**Output:**
<img width="644" height="794" alt="image" src="https://github.com/user-attachments/assets/ed16a13d-02f3-4d82-9f46-c92de2a6c558" />
<img width="884" height="976" alt="image" src="https://github.com/user-attachments/assets/a53eb849-70bd-4408-8163-36e33ee30437" />


**Report explanation — what each presigned URL parameter binds:**

| Parameter | Binds |
|---|---|
| `X-Amz-Algorithm` | The signing algorithm (AWS4-HMAC-SHA256) |
| `X-Amz-Credential` | The access key ID, date, region, service, and `aws4_request` scope |
| `X-Amz-Date` | The timestamp the signature was created |
| `X-Amz-Expires` | The validity window in seconds (60) |
| `X-Amz-SignedHeaders` | The headers included in the signature (`host`) |
| `X-Amz-Signature` | The HMAC signature binding all of the above |

**Why anyone holding the URL before it lapses is fully authorised:** The presigned URL **is** the authorisation. It embeds a valid signature generated with the issuer's secret key. The holder does not need an AWS identity, credentials, or IAM permissions — possession of the unexpired URL is sufficient proof of delegated authority. This is why presigned URLs must be treated as secrets: anyone who obtains the URL (via logs, browser history, referrer headers, or a shared clipboard) can access the object until it expires.

**Report explanation — the condition-key trap:**

The policy is **correct** — but it was evaluated against the wrong environment. The LocalStack endpoint is plain `http://`, so `aws:SecureTransport` is `false` for every request, and the `Deny` matches all of them. On real AWS the endpoint is HTTPS, the condition evaluates to `true`, and the statement only catches genuinely insecure callers. **A condition key must always be evaluated against the environment it will run in, not the one it was written for.**

---

### Task 7 — Versioning, Delete Markers & Data Remanence

**Objective:** Enable versioning, create multiple revisions, delete the object, and recover the original unredacted record.

#### Step 7.1 — Enable versioning

```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket $BUCKET
```

#### Step 7.2 — Create two more revisions

```bash
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text
```

#### Step 7.3 — List all versions

```bash
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

**Output:**
<img width="909" height="775" alt="image" src="https://github.com/user-attachments/assets/05e640ed-a324-4f38-97e3-211983dd083d" />


> The oldest entry is listed with version ID `null` — that is the copy uploaded in Task 1, **before versioning existed**.

#### Step 7.4 — Delete the object

```bash
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt
```

#### Step 7.5 — Observe the delete marker

```bash
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table
```

#### Step 7.6 — Confirm the object is "gone" to an ordinary reader

```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt
```

#### Step 7.7 — Recover the original unredacted record

```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt

cat recovered.txt
```

**Output:**
<img width="972" height="839" alt="image" src="https://github.com/user-attachments/assets/521af672-c2f0-4fc5-ab09-7c3b58100a67" />


#### Step 7.8 — Permanent, per-version deletion

```bash
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,Size]' --output table
```

**Output:**
<img width="848" height="584" alt="image" src="https://github.com/user-attachments/assets/ee4f10ee-447a-45e4-8749-caaf459fdcda" />


> **Caution:** `recovered.txt` contains the original diagnosis — the data you redacted in v3 and then deleted. This is **object-level data remanence**, and it is why "we deleted the record" is not an acceptable answer to a data-subject erasure request under a privacy regime such as the PDPA or GDPR. Removing it for real requires deleting **every version by ID**.

---

### Task 8 — Lifecycle Rules & Cryptographic Erasure

**Objective:** Express a retention policy, then achieve provable deletion through cryptographic erasure by destroying the KMS key.

#### Step 8.1 — Create the lifecycle configuration

```bash
cat > lifecycle.json <<JSON
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Status": "Enabled",
      "Filter": {"Prefix": "confidential/"},
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[0].[ID,Status]' --output table
```

**Output:**
<img width="828" height="835" alt="image" src="https://github.com/user-attachments/assets/3f901dee-72d5-44aa-bab7-1ebd427954c3" />


#### Step 8.2 — Cryptographic erasure: disable and schedule deletion of the KMS key

```bash
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text
```

```bash
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
```

#### Step 8.3 — Attempt to read an object encrypted under the disabled key

```bash
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

**Output (LocalStack may still return the object):**
<img width="941" height="751" alt="image" src="https://github.com/user-attachments/assets/bed05265-433a-4644-b111-5874031d3f00" />


> **Verify or explain:** LocalStack may still return the object because it does not always re-check key state on read. If your read succeeds, demonstrate the same principle at the KMS layer instead — repeat the Lab 3 Task 6 sequence (`kms encrypt` → `disable-key` → `kms decrypt`) and attach the failed decrypt.

**KMS-layer demonstration:**

```bash
# Encrypt a test blob
aws $EP kms encrypt --key-id $KEY_ID --plaintext "patient-data" \
  --query CiphertextBlob --output text > ciphertext.b64

# Disable the key
aws $EP kms disable-key --key-id $KEY_ID

# Attempt to decrypt — should fail
aws $EP kms decrypt --ciphertext-blob fileb://ciphertext.b64
```

**Output:**

```
An error occurred (DisabledException) when calling the Decrypt operation: The key is disabled.
```

#### Evidence

| Screenshot | Description |
|---|---|
| `task8-lifecycle-rules.png` | Lifecycle configuration table showing `RetireConfidentialRecords` / `Enabled` |
| `task8-key-state.png` | `describe-key` showing `PendingDeletion` and the deletion date |
| `task8-failed-decrypt.png` | KMS decrypt failing under a disabled key |

**Report explanation — why cryptographic erasure gives stronger assurance than overwriting:**

Overwriting assumes you can reliably reach and overwrite **every** copy of the data — including replicas, backups, snapshots, cached copies, and disaster-recovery sites. In cloud object storage, you do not control the physical media, and you may not even know all the places a copy exists. Cryptographic erasure sidesteps this entirely: **destroy the key, and every ciphertext copy — wherever it lives — becomes unrecoverable noise.** The assurance is mathematical, not physical. An auditor can verify the key is scheduled for deletion (`PendingDeletion` state with a deletion date) and knows that no amount of data remanence on the provider's disks can recover the plaintext without the key.

---

## 5. Evidence Folder — Screenshots & Outputs

The `Evidence/` folder contains the following labelled screenshots and captured outputs:


---

## 6. Data Classification Table

| Classification | Who may read it | Impact if leaked | Control you will apply |
|---|---|---|---|
| **public** | Anyone (no authentication required) | Negligible — intended for public consumption | No restriction; served anonymously via public-read if desired |
| **internal** | Authenticated staff (DataAnalyst and above) | Operational disruption; minor reputational damage | IAM policy + resource policy `AllowAnalystInternal` scoped to `internal/*` prefix |
| **confidential** | Authorised clinical staff only (explicit allow-list) | Severe — PDPA/GDPR breach, patient harm, regulatory fine, reputational ruin | Explicit `Deny` in bucket policy for all non-authorised principals; SSE-KMS encryption; versioning; lifecycle expiration; cryptographic erasure |

---

## 7. Short-Answer Questions

### 7.1 Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?

The single element is the **asterisk `*`** in the `"Principal"` field of the bucket policy. It grants `s3:GetObject` to **every principal in the world** — anonymous internet users, authenticated users in other AWS accounts, and even unauthenticated HTTP clients.

`Principal: "*"` on a **bucket policy** is more dangerous than an over-broad IAM policy attached to one user because:

- An **IAM policy** is attached to a specific identity. Its blast radius is limited to whatever that identity can do. If the identity is compromised, the attacker inherits its permissions — but the permissions do not extend to anyone else.
- A **bucket policy with `Principal: "*"`** is attached to the **resource** and applies to **everyone**. It does not matter whether the attacker has an AWS account, credentials, or any relationship with the organisation. The bucket is simply open to the world. There is no identity to compromise, no credential to steal, and no login to bypass — the data is served to anyone who knows or guesses the URL.

This is why the archetypal cloud breach is a bucket policy, not a stolen IAM key.

### 7.2 Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?

| | Identity-based policy | Resource-based policy |
|---|---|---|
| **Attached to** | An IAM user, group, or role | A resource (S3 bucket, KMS key, SQS queue) |
| **Controls** | What the identity can do | Who can access the resource, and what they can do |
| **Principal** | Implicit (the identity it is attached to) | Explicit (`"Principal": {"AWS": "..."}` or `"*"`) |
| **Evaluation** | Evaluated as part of the caller's permissions | Evaluated as part of the resource's permissions |

**In Task 4:**

- The request for `internal/roster.txt` was decided by the **resource policy** — specifically the `AllowAnalystInternal` statement, which explicitly allowed the analyst to `s3:GetObject` on `internal/*`. (The identity policy also allowed it, but the resource policy was the deciding factor because the identity policy alone was not sufficient to grant access to a bucket owned by another account.)
- The request for `confidential/record.txt` was decided by the **resource policy** — specifically the `DenyAnalystConfidential` statement, which explicitly denied `s3:*` on `confidential/*`. The identity policy allowed it (`s3:GetObject` on `*`), but the explicit Deny in the resource policy **overrode** the Allow.

**Precedence:** Default deny → any explicit Deny → any explicit Allow. An explicit Deny always wins.

### 7.3 Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?

A **control** is a specific mechanism that enforces a security requirement — for example, a bucket policy that denies public access, or an IAM policy that restricts who can upload objects.

A **guardrail** is a higher-level, often account-wide or organisation-wide, preventative mechanism that **overrides** individual controls. Block Public Access is a guardrail because it does not just enforce a rule on one bucket — it **overrides any bucket policy or ACL** that would make the bucket public, regardless of who created it or when.

The distinction matters for an organisation with many engineers because:

- **Controls depend on correctness.** Every engineer who writes a bucket policy must get it right every time. One mistake — a `Principal: "*"`, a typo in a condition, a copy-pasted policy from a tutorial — creates an exposure.
- **Guardrails are independent of correctness.** Even if an engineer writes a bad policy, Block Public Access refuses the API call. The guardrail does not care about the engineer's intent or skill level.
- **Guardrails scale.** With 500 engineers and 10,000 buckets, auditing every policy for public access is impractical. A single account-level guardrail protects all of them.

In short: controls are what you *should* do; guardrails are what *stops you* from doing the wrong thing even when you forget, misconfigure, or make a mistake.

### 7.4 Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.

**No.** SSE-KMS does **not** protect the confidential record from the analyst in Task 4.

**What SSE-KMS does:**

- It encrypts the object **at rest** on the storage media. If an attacker gains physical access to the disk, or compromises the storage layer, the ciphertext is useless without the KMS key.
- It provides **auditability** — every use of the KMS key is logged in CloudTrail, so you can see who decrypted what and when.
- It enforces **encryption in transit** between S3 and KMS, and it ensures that objects are encrypted before they are written to disk.

**What SSE-KMS does NOT do:**

- It does **not** control **who can call `s3:GetObject`**. The analyst's request in Task 4 was an authorised API call — the analyst had valid credentials, and the request was processed by S3. S3 decrypted the object using the KMS key and returned the plaintext to the analyst. SSE-KMS is transparent to the caller: if you have `s3:GetObject` permission, you get the plaintext, and the encryption is irrelevant to you.
- It does **not** substitute for **authorisation**. The analyst was denied access to `confidential/record.txt` by the **bucket policy**, not by the encryption. If the bucket policy had allowed the analyst, SSE-KMS would have happily decrypted the object and returned it.

**Precise formulation:** Server-side encryption defends against **unauthorised access to the storage medium** (physical theft, disk-level compromise, provider-side snooping). It does **not** defend against **unauthorised API calls by a principal who has been granted `s3:GetObject` permission** — because in that case, the principal is authorised, and encryption is working as designed by decrypting the object for them.

### 7.5 A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.

**Why `delete-object` alone is not compliant:**

In Task 7, `delete-object` wrote a **delete marker** over the object. To an ordinary reader, the object appeared gone (`NoSuchKey`). But the original unredacted record was still present under version ID `null` and was fully recoverable:

```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt
# Output: Patient: Ahmad bin Ali, Diagnosis: confidential
```

The data subject's personal data — the diagnosis — was still stored, still readable, and still recoverable by anyone with `s3:GetObject` and knowledge of the version ID. This is **object-level data remanence**. Under GDPR Article 17 (Right to Erasure) and Malaysia's PDPA, "we deleted the record" is not a valid response if the data remains recoverable. The deletion must be **effective** — the data must be irrecoverable.

**Two mechanisms that make deletion provable:**

1. **Per-version deletion with version listing.** Delete **every version** of the object by ID, then list the versions to prove none remain:
   ```bash
   aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt --version-id null
   aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt --version-id <v2-id>
   aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt --version-id <v3-id>
   aws $EP s3api list-object-versions --bucket $BUCKET --prefix confidential/record.txt
   # Empty output = provable deletion
   ```
   The auditor can inspect the `list-object-versions` output and confirm that no versions and no delete markers remain.

2. **Cryptographic erasure via KMS key deletion.** As demonstrated in Task 8, schedule the KMS key for deletion:
   ```bash
   aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
   aws $EP kms describe-key --key-id $KEY_ID \
     --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
   # Output: PendingDeletion   2026-09-18T06:10:19.099085+08:00
   ```
   Once the key is destroyed, **every copy of the ciphertext** — including versions, replicas, backups, and any snapshots — becomes unrecoverable noise. The auditor can verify the key state (`PendingDeletion` with a deletion date) and know that no amount of data remanence on the provider's disks can recover the plaintext. This is a **mathematical** assurance, not a physical one, and it is the strongest form of provable deletion available in cloud object storage.

### 7.6 You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.

| Command | Control evidenced |
|---|---|
| `aws s3api get-public-access-block --bucket $BUCKET` | **Block Public Access guardrail** — proves all four flags are `true` and the bucket cannot be made public via policy or ACL |
| `aws s3api get-bucket-encryption --bucket $BUCKET` | **Default encryption at rest (SSE-KMS)** — proves every object is encrypted with a customer-managed KMS key without requiring uploader action |
| `aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET` | **Data retention and lifecycle management** — proves a retention policy exists (e.g., `RetireConfidentialRecords`, `Enabled`) and that data is expired according to policy |

**Additional evidence commands (for completeness):**

| Command | Control evidenced |
|---|---|
| `aws s3api get-bucket-versioning --bucket $BUCKET` | **Versioning** — proves versioning is enabled (supports recovery and audit) |
| `aws kms describe-key --key-id $KEY_ID` | **Cryptographic erasure** — proves the key is `PendingDeletion` with a deletion date |
| `aws s3api get-bucket-policy --bucket $BUCKET` | **Least-privilege resource policy** — proves no `Principal: "*"` and that access is scoped by prefix |

---

## 8. Verification Command Output

Paste the output of the following block to prove the bucket's final security posture:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="

aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text

aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text

aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' --output text

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[0].[ID,Status]' --output text
```

**Output:**

<img width="1120" height="606" alt="image" src="https://github.com/user-attachments/assets/3b4ca102-a1aa-4130-aec0-19e8678505c9" />


**Interpretation:**

| Check | Result | Status |
|---|---|---|
| Block Public Access (4 flags) | `True True True True` | ✅ All four guardrails enabled |
| Versioning | `Enabled` | ✅ Versioning active |
| Default encryption | `aws:kms` + key ARN | ✅ SSE-KMS with customer-managed key |
| Lifecycle rules | `RetireConfidentialRecords Enabled` | ✅ Retention policy in force |

---

## 9. Security Best-Practices Checklist

| # | Best Practice | Status | Evidence |
|---|---|---|---|
| 1 | Every object carries a classification tag before any access decision is made | ✅ | Task 1: `classification=public/internal/confidential` |
| 2 | No bucket policy names `Principal: "*"`; anonymous access was tested and is refused | ✅ | Task 3: Block Public Access; anonymous read refused |
| 3 | Block Public Access is enabled on all four flags | ✅ | Task 3: `get-public-access-block` all `true` |
| 4 | Access is granted by least privilege and scoped to a key prefix, never to `*` by default | ✅ | Task 4: `AllowAnalystInternal` scoped to `internal/*` |
| 5 | Default encryption at rest is `aws:kms` with a customer-managed key | ✅ | Task 5: `get-bucket-encryption` shows `aws:kms` + key ARN |
| 6 | Sharing uses time-bounded presigned URLs, not permanent public objects | ✅ | Task 6: 60-second expiry, HTTP 403 after |
| 7 | Versioning is enabled, and the team understands that delete markers do not destroy data | ✅ | Task 7: version listing + delete marker + recovery |
| 8 | A lifecycle configuration expresses the retention policy, and cryptographic erasure is available for provable deletion | ✅ | Task 8: `RetireConfidentialRecords` + KMS key `PendingDeletion` |

---



---

## 11. Reflection & Lessons Learned

This lab demonstrated that object storage security is fundamentally about **policy precedence** and **defence in depth**. The archetypal breach — a bucket policy with `Principal: "*"` — required no exploit, no malware, and no vulnerability. It was a single configuration mistake that exposed confidential patient data to the entire internet. The remediation taught two lessons:

1. **Preventative guardrails beat detective controls.** Block Public Access does not merely report that a bucket is public — it refuses the API call that would make it public. In an organisation with many engineers, this is the difference between locking the door and installing a camera that films the burglary.

2. **Encryption does not substitute for authorisation.** SSE-KMS protects data at rest, but it does not stop an authorised caller from retrieving plaintext. The analyst in Task 4 was denied by the **bucket policy**, not by the encryption. This distinction is critical: encryption and access control are complementary, not interchangeable.

The versioning task revealed **object-level data remanence** — the uncomfortable truth that `delete-object` does not delete data when versioning is enabled. A data-subject erasure request cannot be satisfied by a delete marker; it requires per-version deletion or cryptographic erasure. The KMS key deletion task showed that **cryptographic erasure** provides a stronger, more provable assurance than overwriting, because it does not depend on reaching every physical copy of the data — it makes every copy unrecoverable by destroying the one thing they all depend on.

Finally, the `aws:SecureTransport` condition-key trap was a sobering reminder that **a correct policy can still be wrong** if it is evaluated against the wrong environment. A policy written for HTTPS will lock you out of an HTTP endpoint — and the same principle applies in production when a policy written for one region, one account, or one network topology is deployed into a different one. Always test policies against the environment they will run in, not the one they were written for.

---

**End of Report**
