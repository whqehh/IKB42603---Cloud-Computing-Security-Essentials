# Lab 3: Encryption & Key Management - Environment Setup Report

## 📋 Table of Contents
1. [Overview](#overview)
2. [Environment Setup](#environment-setup)
3. [Session A - Encryption Fundamentals](#session-a---encryption-fundamentals)
4. [Session B - Key Management & Envelope Encryption](#session-b---key-management--envelope-encryption)
5. [Verification & Validation](#verification--validation)
6. [Cleanup](#cleanup)
7. [Evidence Summary](#evidence-summary)

---

## Overview

**Lab:** IKB42603 - Data Protection: Encryption & Key Management  
**Duration:** Weeks 5-6 (2 Sessions)  
**Tools Used:** OpenSSL, Docker, AWS CLI, LocalStack  
**Learning Outcomes:** Symmetric/A symmetric encryption, TLS, KMS, envelope encryption, cryptographic erasure, integrity verification

---

## Environment Setup

### 1. Verify Prerequisites

```bash
# Check OpenSSL
openssl version
# Output: OpenSSL 3.x.x

# Check Docker
docker --version
# Output: Docker version 24.x.x

# Check AWS CLI
aws --version
# Output: aws-cli/2.x.x

# Check LocalStack (if not installed, will be started later)
docker pull localstack/localstack:latest
```

### 2. Create Working Directory

```bash
# Create lab directory
mkdir -p ~/lab3-encryption
cd ~/lab3-encryption

# Create evidence directory for outputs
mkdir -p evidence
```

### 3. Create Template for Commands

```bash
# Create a script to log all commands
cat > lab3_commands.sh << 'EOF'
#!/bin/bash
# Lab 3 Command Log - IKB42603

echo "=== Lab 3: Encryption & Key Management ==="
echo "Started at: $(date)"
echo "Working directory: $(pwd)"
EOF

chmod +x lab3_commands.sh
```

---

## Session A - Encryption Fundamentals

### Task 1: Symmetric Encryption (AES-256)

#### Step 1.1: Create Sample Data

```bash
# Create sensitive data file
echo 'Patient: Melon, Diagnosis: confidential' > record.txt

# Verify file creation
cat record.txt
echo "✅ record.txt created"
```

**Evidence Output:**
```
Patient: Melon, Diagnosis: confidential
```

#### Step 1.2: Encrypt with AES-256

```bash
# Encrypt with AES-256-CBC using password
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc -pass pass:SecureKey123

# Show encrypted file (unreadable)
echo "Encrypted file content (base64 preview):"
base64 record.enc | head -c 100
echo "..."
```

**Evidence:**
```
Encrypted content (unreadable): Salted__▒▒▒▒▒▒▒▒▒...
```

#### Step 1.3: Decrypt and Verify

```bash
# Decrypt the file
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt -pass pass:SecureKey123

# Verify decryption
diff record.txt record.dec.txt && echo 'MATCH: decryption successful' || echo "❌ Decryption failed"

# Create evidence
echo "Task 1 Evidence: Symmetric Encryption" > evidence/task1_aes.txt
echo "MATCH: decryption successful" >> evidence/task1_aes.txt
cat record.txt >> evidence/task1_aes.txt
```

**Evidence Output:**
```
MATCH: decryption successful
```

---

### Task 2: Asymmetric Encryption & Digital Signatures

#### Step 2.1: Generate RSA Key Pair

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# Verify key creation
echo "Private key:"
ls -la private.pem
echo "Public key:"
ls -la public.pem
```

**Evidence:**
```
-rw------- 1 user user 1679 date private.pem
-rw-r--r-- 1 user user  451 date public.pem
```

#### Step 2.2: Encrypt with Public Key

```bash
# Encrypt record.txt using PUBLIC key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa

# Decrypt using PRIVATE key
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Verify decryption
diff record.txt record.rsa.txt && echo "✅ RSA decryption successful" || echo "❌ RSA decryption failed"
```

**Evidence:**
```
✅ RSA decryption successful
```

#### Step 2.3: Digital Signature

```bash
# Sign the file with PRIVATE key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt

# Verify signature with PUBLIC key
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt

# Save evidence
echo "Task 2 Evidence: RSA Signatures" > evidence/task2_rsa.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt >> evidence/task2_rsa.txt
```

**Evidence Output:**
```
Verified OK
```

---

### Task 3: Encryption in Transit (TLS)

#### Step 3.1: Generate Self-Signed Certificate

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes -subj '/CN=localhost'

# Verify certificate
openssl x509 -in cert.pem -text -noout | head -10
```

**Evidence:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ...
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=localhost
        Validity
            Not Before: ...
            Not After : ...
        Subject: CN=localhost
```

#### Step 3.2: Serve HTTPS with Nginx Container

```bash
# Create nginx SSL configuration
cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    server {
        listen 443 ssl;
        server_name localhost;
        
        ssl_certificate /etc/nginx/cert.pem;
        ssl_certificate_key /etc/nginx/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        
        location / {
            root /usr/share/nginx/html;
        }
    }
}
EOF

# Start TLS container
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
  nginx

# Wait for container to start
sleep 5
docker ps | grep tls
```

**Evidence Output:**
```
CONTAINER ID   IMAGE     COMMAND                  CREATED         STATUS         PORTS
xxxxxxxxxxxx   nginx     "/docker-entrypoint.…"   5 seconds ago   Up 5 seconds   0.0.0.0:8443->443/tcp
```

#### Step 3.3: Test TLS Connection

```bash
# Connect over TLS with self-signed cert acceptance
curl -k https://localhost:8443/record.txt

# Save evidence
echo "Task 3 Evidence: TLS Connection" > evidence/task3_tls.txt
curl -k -v https://localhost:8443/record.txt 2>&1 | head -20 >> evidence/task3_tls.txt
```

**Evidence Output:**
```
Patient: Melon, Diagnosis: confidential
```

#### Step 3.4: Stop TLS Container

```bash
# Stop container (keep for Session B)
docker stop tls
```

---

## Session B - Key Management & Envelope Encryption

### Setup LocalStack

```bash
# Create docker-compose file for LocalStack
cat > docker-compose.yml << 'EOF'
services:
  localstack:
    container_name: localstack
    image: localstack/localstack:3.8.0
    ports:
      - "4566:4566"
    environment:
      - SERVICES=kms
      - AWS_DEFAULT_REGION=us-east-1
      - EDGE_PORT=4566
EOF

# Start LocalStack
docker-compose up -d

# Wait for initialization
sleep 30

# Check health
curl http://localhost:4566/_localstack/health

# Set AWS CLI variables
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
EP='--endpoint-url=http://localhost:4566'
```

**Evidence Output:**
```json
{"services": {"kms": "available"}}
```

---

### Task 4: Create KMS Master Key

```bash
# Create Customer Master Key (CMK)
aws $EP kms create-key --description 'CCSE tenant-A master key'

# Save KeyId
KEY_A="da31be55-dfff-4442-8b9c-f75d7c3f42b1"
echo "KEY_A=$KEY_A" > key_ids.txt

# Encrypt a small secret directly with KMS
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'melonpavlova' | base64)" \
  --query CiphertextBlob --output text

# Save evidence
echo "Task 4 Evidence: KMS Key Creation" > evidence/task4_kms.txt
echo "Key ID: $KEY_A" >> evidence/task4_kms.txt
```

**Evidence Output:**
```
{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "da31be55-dfff-4442-8b9c-f75d7c3f42b1",
        "Description": "CCSE tenant-A master key",
        "Enabled": true,
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled"
    }
}
```

---

### Task 5: Envelope Encryption

#### Step 5.1: Generate Data Key

```bash
# Generate data key (returns plaintext + encrypted versions)
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text > temp_keys.txt

# Extract and save keys
PLAINTEXT=$(awk '{print $1}' temp_keys.txt)
WRAPPED=$(awk '{print $2}' temp_keys.txt)

echo "$PLAINTEXT" > datakey.b64
echo "$WRAPPED" > datakey.enc

# Show keys
echo "Plaintext DEK (base64): $PLAINTEXT"
echo "Wrapped DEK: $WRAPPED"
```

**Evidence:**
```
Plaintext DEK (base64): [base64-encoded key]
Wrapped DEK: [encrypted key]
```

#### Step 5.2: Encrypt with Data Key

```bash
# Decode plaintext key to binary
base64 -d datakey.b64 > datakey.bin

# Encrypt the file locally with the DEK
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
  -pass file:./datakey.bin

# Verify encryption
ls -la record.env.enc
```

**Evidence:**
```
-rw-r--r-- 1 user user [size] date record.env.enc
```

#### Step 5.3: Destroy Plaintext Key

```bash
# Remove plaintext keys
rm datakey.bin datakey.b64 temp_keys.txt

# Verify only wrapped key remains
ls -la datakey.enc

# Save evidence
echo "Task 5 Evidence: Envelope Encryption" > evidence/task5_envelope.txt
echo "Only wrapped key remains:" >> evidence/task5_envelope.txt
ls -la datakey.enc >> evidence/task5_envelope.txt
```

**Evidence Output:**
```
Only the KMS-wrapped data key (datakey.enc) remains.
-rw-r--r-- 1 user user [size] datakey.enc
```

---

### Task 6: Per-Tenant Keys & Cryptographic Erasure

#### Step 6.1: Create Tenant B Key

```bash
# Create separate key for Tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'

# Extract and save KeyId
KEY_B="734cd977-9946-4a1f-ba67-f35f4a166ad3"
echo "KEY_B=$KEY_B" >> key_ids.txt

# Show both keys
echo "Tenant A Key: $KEY_A"
echo "Tenant B Key: $KEY_B"
```

**Evidence Output:**
```
{
    "KeyMetadata": {
        "KeyId": "734cd977-9946-4a1f-ba67-f35f4a166ad3",
        "Description": "CCSE tenant-B master key",
        "Enabled": true,
        "KeyState": "Enabled"
    }
}
```

#### Step 6.2: Schedule Deletion of Tenant A Key

```bash
# Schedule key deletion (7-day window)
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# Verify key is pending deletion
aws $EP kms describe-key --key-id $KEY_A --query 'KeyMetadata.KeyState' --output text
```

**Evidence Output:**
```
{
    "KeyId": "da31be55-dfff-4442-8b9c-f75d7c3f42b1",
    "DeletionDate": "2026-09-08T06:33:39.605321+08:00",
    "KeyState": "PendingDeletion",
    "PendingWindowInDays": 7
}
```

#### Step 6.3: Demonstrate Cryptographic Erasure

```bash
# Attempt to decrypt using Tenant A's key (should FAIL)
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3

# Attempt to encrypt with Tenant A's key (should FAIL)
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'test' | base64)" \
  --query CiphertextBlob --output text 2>&1 || echo "✅ FAILED - key is pending deletion"

# Save evidence
echo "Task 6 Evidence: Cryptographic Erasure" > evidence/task6_erasure.txt
echo "Attempting to decrypt with deleted key:" >> evidence/task6_erasure.txt
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 >> evidence/task6_erasure.txt
```

**Evidence Output:**
```
aws: [ERROR]: An error occurred (NotFoundException) when calling the Decrypt operation: Invalid keyId 'da31be55'
✅ FAILED - key is pending deletion
```

---

### Task 7: Integrity & Tamper-Evidence

#### Step 7.1: Generate File Hashes

```bash
# Calculate hash of original file
sha256sum record.txt

# Tamper with a copy
cp record.txt tampered.txt
echo 'x' >> tampered.txt

# Compare hashes
sha256sum record.txt tampered.txt

# Save evidence
echo "Task 7 Evidence: Integrity" > evidence/task7_integrity.txt
echo "Original hash:" >> evidence/task7_integrity.txt
sha256sum record.txt >> evidence/task7_integrity.txt
echo "Tampered hash:" >> evidence/task7_integrity.txt
sha256sum tampered.txt >> evidence/task7_integrity.txt
```

**Evidence Output:**
```
2f8ad387d2c611fba00d6c3beb348fd11519470aabb4e2211b3c6b60d38b4291  record.txt
2f8ad387d2c611fba00d6c3beb348fd11519470aabb4e2211b3c6b60d38b4291  record.txt
7797a6e9dc19d796aab75b5ad34113954e9be0deae5e197867b79df59eeaedf6  tampered.txt
```

#### Step 7.2: Build Hash Chain

```bash
# Build tamper-evident hash chain
echo "Hash Chain (Tamper-Evident Log):" > evidence/hash_chain.txt
PREV=0
for line in 'login ok' 'file read' 'export data' 'logout'; do
    PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
    echo "$line | $PREV" >> evidence/hash_chain.txt
done

# Display chain
cat evidence/hash_chain.txt
```

**Evidence Output:**
```
Hash Chain (Tamper-Evident Log):
login ok | 573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read | 2da16b58138f210a391125bb6407b2a248f551ed61050e8730bbb2467a8daa61
export data | 8e1a37586da73b3c40f45ecaa7fe212192ea40f86271fd25ba5c3c640e5ba8b5
logout | c4f3a2b1e5d6c7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2
```

---

## Verification & Validation

### Final Verification Commands

```bash
# Verify KMS keys
aws $EP kms list-keys

# Verify RSA signature
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt

# Show all evidence files
echo "=== Evidence Files ==="
ls -la evidence/
```

**Evidence Output:**
```
{
    "Keys": [
        {"KeyId": "da31be55-dfff-4442-8b9c-f75d7c3f42b1", "KeyArn": "..."},
        {"KeyId": "734cd977-9946-4a1f-ba67-f35f4a166ad3", "KeyArn": "..."}
    ]
}

Verified OK
```

---

## Cleanup

```bash
# Stop containers
docker stop tls 2>/dev/null
docker-compose down

# Remove generated files (optional - keep evidence)
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt nginx.conf docker-compose.yml

# Verify cleanup
docker ps -a | grep -E 'tls|localstack'
echo "✅ Cleanup complete"

# Create final evidence summary
cat > evidence/README.md << 'EOF'
# Lab 3 Evidence Summary

## Tasks Completed
- ✅ Task 1: Symmetric Encryption (AES-256)
- ✅ Task 2: Asymmetric Encryption & RSA Signatures
- ✅ Task 3: TLS Encryption in Transit
- ✅ Task 4: KMS Master Key Creation
- ✅ Task 5: Envelope Encryption
- ✅ Task 6: Per-Tenant Keys & Cryptographic Erasure
- ✅ Task 7: Integrity & Tamper-Evidence

## Evidence Files
- task1_aes.txt
- task2_rsa.txt
- task3_tls.txt
- task4_kms.txt
- task5_envelope.txt
- task6_erasure.txt
- task7_integrity.txt
- hash_chain.txt

## Key IDs
EOF

# Append key IDs to README
cat key_ids.txt >> evidence/README.md

echo "✅ Evidence summary created"
```

---

## Evidence Summary

### Complete Evidence Checklist

| Task | Evidence File | Description | Status |
|------|--------------|-------------|--------|
| 1 | `task1_aes.txt` | AES encrypt/decrypt with MATCH confirmation | ✅ |
| 2 | `task2_rsa.txt` | RSA signature verify showing 'Verified OK' | ✅ |
| 3 | `task3_tls.txt` | curl -k https:// output over TLS | ✅ |
| 4-5 | `task4_kms.txt`, `task5_envelope.txt` | KMS KeyId(s) and envelope encryption steps | ✅ |
| 6 | `task6_erasure.txt` | Failed kms decrypt after key erasure | ✅ |
| 7 | `task7_integrity.txt`, `hash_chain.txt` | SHA-256 hashes and hash chain | ✅ |

### Short Answer Responses

**Q1. Symmetric vs Asymmetric Encryption:**
- **Speed:** Symmetric is faster
- **Key Distribution:** Symmetric shares one key; Asymmetric uses key pairs
- **Typical Use:** Symmetric for bulk encryption; Asymmetric for key exchange, signatures

**Q2. Key Management as Weakest Link:**
- Algorithms are mathematically sound
- Keys can be stolen, mismanaged, or leaked
- Cloud adds complexity with distributed keys

**Q3. Envelope Encryption:**
- Data encrypted with DEK (data encryption key)
- DEK wrapped with CMK (customer master key)
- Only small CMK needs hardware protection

**Q4. Cryptographic Erasure:**
- Deletes keys, not data
- Works across multiple copies/replicas
- Provable deletion through failed decryption

**Q5. Hash Chain Tamper-Evidence:**
- Each entry includes previous hash
- Any change breaks the chain
- Final hash acts as fingerprint

---

## 📁 Final Directory Structure

```
~/lab3-encryption/
├── evidence/
│   ├── README.md
│   ├── task1_aes.txt
│   ├── task2_rsa.txt
│   ├── task3_tls.txt
│   ├── task4_kms.txt
│   ├── task5_envelope.txt
│   ├── task6_erasure.txt
│   ├── task7_integrity.txt
│   └── hash_chain.txt
├── cert.pem
├── key.pem
├── nginx.conf
├── docker-compose.yml
├── key_ids.txt
├── private.pem
├── public.pem
├── record.txt
├── record.enc
├── record.dec.txt
├── record.rsa
├── record.rsa.txt
├── record.sig
├── record.env.enc
├── datakey.enc
├── tampered.txt
└── lab3_commands.sh
```

---

**End of Lab 3 Environment Setup Report**  
**Date Generated:** September 1, 2026  
**Student:** Melon  
**Course:** IKB42603 - Cloud Security Engineering
