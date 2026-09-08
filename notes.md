```markdown
# Cloud Computing Security Essentials - Command Reference

> A comprehensive collection of all essential commands for the skill-based assessment

---

## 🛠️ Environment Setup (LocalStack & AWS CLI)

### Start LocalStack
```bash
# Remove any existing container
docker rm -f localstack 2>/dev/null

# Start LocalStack container
docker run -d --name localstack -p 4566:4566 localstack/localstack

# Wait for it to be ready
until curl -sf http://localhost:4566/_localstack/health > /dev/null; do sleep 2; done
```

### Configure AWS CLI
```bash
# Set endpoint variable (use this in all commands)
export EP='--endpoint-url=http://localhost:4566'

# Configure dummy credentials
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# Test it works - SAVE THIS OUTPUT (it's evidence!)
aws $EP sts get-caller-identity
```

---

## 🔐 IAM (Lab 1)

### Create Admin Group & User

```bash
# Create Admins group
aws $EP iam create-group --group-name Admins

# Attach admin policy to group
aws $EP iam attach-group-policy \
    --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create admin user (replace YOURNAME)
aws $EP iam create-user --user-name CloudAdmin_YOURNAME

# Add user to group
aws $EP iam add-user-to-group \
    --group-name Admins \
    --user-name CloudAdmin_YOURNAME

# Verify membership - EVIDENCE
aws $EP iam get-group --group-name Admins
```

### Create Read-Only User

```bash
# Create read-only user
aws $EP iam create-user --user-name Analyst_YOURNAME

# Attach S3 read-only policy
aws $EP iam attach-user-policy \
    --user-name Analyst_YOURNAME \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Verify attached policies - EVIDENCE
aws $EP iam list-attached-user-policies --user-name Analyst_YOURNAME
```

### Access Key Management

```bash
# Create access key
aws $EP iam create-access-key --user-name Analyst_YOURNAME

# List access keys
aws $EP iam list-access-keys --user-name Analyst_YOURNAME

# Deactivate a key (rotate)
aws $EP iam update-access-key \
    --user-name Analyst_YOURNAME \
    --access-key-id <PASTE_KEY_ID> \
    --status Inactive
```

### Cleanup IAM Resources

```bash
# Detach policies
aws $EP iam detach-user-policy \
    --user-name Analyst_YOURNAME \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

aws $EP iam detach-group-policy \
    --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Remove user from group
aws $EP iam remove-user-from-group \
    --group-name Admins \
    --user-name CloudAdmin_YOURNAME

# Delete users
aws $EP iam delete-user --user-name Analyst_YOURNAME
aws $EP iam delete-user --user-name CloudAdmin_YOURNAME

# Delete group
aws $EP iam delete-group --group-name Admins
```

---

## ☸️ Kubernetes RBAC (Lab 1 Session B)

### Create Cluster

```bash
# Create kind cluster
kind create cluster --name ccse-lab1

# Verify it's running
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

### Setup Namespaces and RBAC

```bash
# Create namespaces
kubectl create namespace dev
kubectl create namespace prod

# Create service account
kubectl create serviceaccount dev-user -n dev

# Create role with minimal permissions
kubectl create role pod-reader -n dev \
    --verb=get,list,watch \
    --resource=pods

# Bind role to service account
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader \
    --serviceaccount=dev-user
```

### Test RBAC (EVIDENCE)

```bash
# Define service account reference
SA=system:serviceaccount:dev:dev-user

# Should be YES - reading pods in dev is allowed
kubectl auth can-i list pods -n dev --as=$SA

# Should be NO - deleting pods is not granted
kubectl auth can-i delete pods -n dev --as=$SA

# Should be NO - role does not extend to prod
kubectl auth can-i list pods -n prod --as=$SA
```

### Cleanup

```bash
# Delete the cluster
kind delete cluster --name ccse-lab1
```

---

## 🔒 Network Policies (Lab 2)

### Setup for Lab 2

```bash
# Create cluster with Calico (for network policy enforcement)
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

# Install Calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s

# Create namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy web services
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

### Default-Deny Ingress Policy

```bash
# Apply default-deny ingress to tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

### Test Ingress Policy

```bash
# Get tenant-b service IP
B_IP=$(kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}')

# Before policy - should work (HTTP 200)
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never -- \
    curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'

# After policy - should timeout/fail
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never -- \
    curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'
```

### Resource Quotas

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

# Check quota
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

### Egress Default-Deny (Zero Trust Addendum)

```bash
# Test default egress (should work - unrestricted)
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
    sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"

# Apply egress policy
cat > egress-policy.yaml << 'YML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-and-api-only
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  - to:
    - podSelector:
        matchLabels:
          app: api
    ports:
    - protocol: TCP
      port: 80
YML

kubectl apply -f egress-policy.yaml

# Test again - should be BLOCKED
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
    sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"

# In-namespace should still work
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
    sh -c "wget -qO- --timeout=3 http://api.tenant-a.svc.cluster.local || echo BLOCKED"
```

---

## 🛡️ Pod Security Standards (Lab 2 Addendum)

### Enforce Restricted Policy

```bash
# Label namespace for restricted enforcement
kubectl label namespace tenant-a \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    --overwrite

# Verify labels
kubectl get namespace tenant-a --show-labels
```

### Test Privileged Pod (Should be REJECTED)

```bash
cat > privileged-pod.yaml << 'YML'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-probe
  namespace: tenant-a
spec:
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
YML

# This should be REJECTED by admission controller
kubectl apply -f privileged-pod.yaml
```

### Deploy Compliant Pod (Should SUCCEED)

```bash
cat > compliant-pod.yaml << 'YML'
apiVersion: v1
kind: Pod
metadata:
  name: compliant-probe
  namespace: tenant-a
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
YML

kubectl apply -f compliant-pod.yaml
kubectl -n tenant-a get pod compliant-probe
```

### Cleanup Pod Security

```bash
kubectl delete -f egress-policy.yaml --ignore-not-found
kubectl delete pod compliant-probe -n tenant-a --ignore-not-found
kubectl label namespace tenant-a \
    pod-security.kubernetes.io/enforce- \
    pod-security.kubernetes.io/enforce-version- \
    pod-security.kubernetes.io/warn- 2>/dev/null
```

---

## 🔐 KMS & Envelope Encryption (Lab 3)

### Create KMS Key

```bash
# Create customer master key
KEY_A=$(aws $EP kms create-key \
    --description 'CCSE tenant-A master key' \
    --query 'KeyMetadata.KeyId' \
    --output text)

echo "Key ID: $KEY_A"
```

### Direct KMS Encryption

```bash
# Encrypt small secret directly with KMS
aws $EP kms encrypt \
    --key-id $KEY_A \
    --plaintext "$(echo -n 'hello' | base64)" \
    --query CiphertextBlob \
    --output text
```

### Envelope Encryption

```bash
# 1. Generate data key
aws $EP kms generate-data-key \
    --key-id $KEY_A \
    --key-spec AES_256 \
    --query '[Plaintext,CiphertextBlob]' \
    --output text

# Save outputs (column 1 = plaintext, column 2 = encrypted)
# Column 1 > datakey.b64, Column 2 > datakey.enc

# 2. Decode plaintext key
base64 -d datakey.b64 > datakey.bin

# 3. Encrypt file with data key
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin

# 4. Destroy plaintext key
rm datakey.bin datakey.b64
```

### Cryptographic Erasure

```bash
# Create second tenant key
KEY_B=$(aws $EP kms create-key \
    --description 'CCSE tenant-B master key' \
    --query 'KeyMetadata.KeyId' \
    --output text)

# Schedule deletion of tenant A's key
aws $EP kms schedule-key-deletion \
    --key-id $KEY_A \
    --pending-window-in-days 7

# Disable immediately
aws $EP kms disable-key --key-id $KEY_A

# Attempt to decrypt - should FAIL
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc
```

### Cleanup KMS

```bash
# Cancel deletion if needed
aws $EP kms cancel-key-deletion --key-id $KEY_A

# Schedule deletion for both keys
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7
aws $EP kms schedule-key-deletion --key-id $KEY_B --pending-window-in-days 7
```

---

## 🔐 Encryption with OpenSSL (Lab 3)

### Symmetric Encryption (AES-256)

```bash
# Create sample file
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# Encrypt
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# View encrypted (unreadable)
cat record.enc

# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt

# Verify
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

### Asymmetric Encryption (RSA)

```bash
# Generate key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with PUBLIC key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa

# Decrypt with PRIVATE key
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Sign with PRIVATE key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt

# Verify with PUBLIC key - EVIDENCE
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

### TLS/HTTPS

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 7 -nodes -subj '/CN=localhost'

# Serve HTTPS
docker run -d --rm --name tls -p 8443:443 \
    -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
    -v $(pwd)/key.pem:/etc/nginx/key.pem \
    -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
    nginx:alpine

# Connect over TLS (-k accepts self-signed)
curl -k https://localhost:8443/record.txt

# Stop container
docker stop tls
```

---

## 📊 Logging & Monitoring (Lab 5)

### Setup CloudWatch Logs

```bash
# Create log group and stream
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

### Generate and Ship Logs

```bash
# Create auth log
cat > auth.log << 'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF

# Ship to CloudWatch
TS=$(date +%s%3N)
while IFS= read -r line; do
    aws $EP logs put-log-events \
        --log-group-name /ccse/app \
        --log-stream-name auth \
        --log-events timestamp=$TS,message="$line" >/dev/null
    TS=$((TS+1000))
done < auth.log

# Read back - EVIDENCE
aws $EP logs get-log-events \
    --log-group-name /ccse/app \
    --log-stream-name auth \
    --query 'events[].message' \
    --output text
```

### Query for Security Events

```bash
# Count failed logins by IP - EVIDENCE
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

### Hash-Chained Tamper-Proof Logs

```bash
# Create hash chain
PREV=0
while IFS= read -r line; do
    PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
    printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

# View chain
cat auth.chain

# Tamper with log
sed 's/500MB/5MB/' auth.log > auth.tampered

# Detect tampering - compare final hashes
tail -1 auth.chain
```

### Incident Detection & Response

```bash
# Detect brute-force pattern
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
    echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi

# Contain - block IP
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
    "apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n"

# Collect evidence
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

### Cleanup

```bash
rm -f auth.log auth.chain auth.tampered evidence_*.log evidence.sha256
```

---

## 📦 S3 & Object Storage (Lab 6)

### Create Bucket with Classification

```bash
# Create bucket
export BUCKET=mii-patient-records-$RANDOM
echo $BUCKET
aws $EP s3api create-bucket --bucket $BUCKET

# Create classification files
echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

# Upload with tags
aws $EP s3api put-object \
    --bucket $BUCKET \
    --key public/notice.txt \
    --body public-notice.txt \
    --tagging 'classification=public'

aws $EP s3api put-object \
    --bucket $BUCKET \
    --key internal/roster.txt \
    --body internal-roster.txt \
    --tagging 'classification=internal'

aws $EP s3api put-object \
    --bucket $BUCKET \
    --key confidential/record.txt \
    --body confidential-record.txt \
    --tagging 'classification=confidential'

# List objects
aws $EP s3api list-objects-v2 --bucket $BUCKET \
    --query 'Contents[].[Key,Size]' --output table

# Get tags
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

### Reproduce Breach

```bash
# Create public policy
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadEverything",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3::$BUCKET/*"
    }
  ]
}
JSON

# Apply policy
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# Anonymous read - should work (HTTP 200)
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
    http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

### Block Public Access

```bash
# Delete public policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# Apply Block Public Access
aws $EP s3api put-public-access-block --bucket $BUCKET \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verify - EVIDENCE
aws $EP s3api get-public-access-block --bucket $BUCKET

# Try to re-apply public policy (should fail)
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# Test anonymous read (should fail)
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
    http://localhost:4566/$BUCKET/confidential/record.txt
```

### Least-Privilege Bucket Policy

```bash
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccountReadInternalOnly",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3::$BUCKET/internal/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
```

### Default Encryption (SSE-KMS)

```bash
# Create KMS key for bucket
KEY_ID=$(aws $EP kms create-key \
    --description 'IKB42603 Lab6 patient records bucket key' \
    --query 'KeyMetadata.KeyId' --output text)

# Apply bucket encryption
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

aws $EP s3api put-bucket-encryption \
    --bucket $BUCKET \
    --server-side-encryption-configuration file://encryption.json

# Verify
aws $EP s3api get-bucket-encryption --bucket $BUCKET

# Upload without encryption flags - bucket applies it
aws $EP s3api put-object \
    --bucket $BUCKET \
    --key confidential/record-v2.txt \
    --body confidential-record.txt

# Check encryption - EVIDENCE
aws $EP s3api head-object \
    --bucket $BUCKET \
    --key confidential/record-v2.txt \
    --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' \
    --output text
```

### Versioning & Delete Markers

```bash
# Enable versioning
aws $EP s3api put-bucket-versioning \
    --bucket $BUCKET \
    --versioning-configuration Status=Enabled

# Create versions
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object \
    --bucket $BUCKET \
    --key confidential/record.txt \
    --body rec-v2.txt

aws $EP s3api put-object \
    --bucket $BUCKET \
    --key confidential/record.txt \
    --body rec-v3.txt

# List versions
aws $EP s3api list-object-versions \
    --bucket $BUCKET \
    --prefix confidential/record.txt \
    --query 'Versions[].[VersionId,IsLatest,Size]' \
    --output table

# Delete (writes delete marker)
aws $EP s3api delete-object \
    --bucket $BUCKET \
    --key confidential/record.txt

# List delete markers
aws $EP s3api list-object-versions \
    --bucket $BUCKET \
    --prefix confidential/record.txt \
    --query 'DeleteMarkers[].[VersionId,IsLatest]' \
    --output table

# Get previous version (still exists!)
aws $EP s3api get-object \
    --bucket $BUCKET \
    --key confidential/record.txt \
    --version-id null \
    recovered.txt

cat recovered.txt
```

### Lifecycle Rules

```bash
cat > lifecycle.json << 'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration \
    --bucket $BUCKET \
    --lifecycle-configuration file://lifecycle.json
```

### Presigned URLs

```bash
# Generate presigned URL
URL=$(aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60)
echo $URL

# Download with presigned URL
curl -s -w 'HTTP %{http_code}\n' "$URL"

# Wait and try again (should expire)
sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

### Secure Transport Condition Trap

```bash
cat > secure-transport.json <<JSON
{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Sid":"DenyUnencryptedTransport",
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:*",
      "Resource":["arn:aws:s3::$BUCKET","arn:aws:s3::$BUCKET/*"],
      "Condition":{"Bool":{"aws:SecureTransport":"false"}}
    }
  ]
}
JSON

# This will lock you out (LocalStack uses HTTP)
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

# These will fail
aws $EP s3api list-objects-v2 --bucket $BUCKET

# Recover
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

### Cleanup S3 (with versioning)

```bash
# Delete all object versions
aws $EP s3api delete-objects \
    --bucket $BUCKET \
    --delete "$(aws $EP s3api list-object-versions --bucket $BUCKET --output json --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# Delete all delete markers
aws $EP s3api delete-objects \
    --bucket $BUCKET \
    --delete "$(aws $EP s3api list-object-versions --bucket $BUCKET --output json --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

# Verify empty
aws $EP s3api list-object-versions --bucket $BUCKET --output text

# Delete bucket
aws $EP s3api delete-bucket --bucket $BUCKET
```

---

## 🐳 Docker Network Segmentation (Lab 4)

```bash
# Create networks
docker network create frontend-net
docker network create backend-net

# Deploy services
docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx

# Test web -> db (should FAIL)
docker exec web sh -c 'apk add -q curl; curl -s -m 3 db:6379 || echo BLOCKED'

# Test app -> db (should WORK)
docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
```

### Firewall Default-Deny

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
    apk add -q iptables;
    iptables -P INPUT DROP;
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT;
    iptables -A INPUT -i lo -j ACCEPT;
    iptables -L INPUT -n'
```

### Container Hardening

```bash
# Run hardened container
docker run -d --name hardened \
    --user 1000:1000 \
    --read-only \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp \
    nginxinc/nginx-unprivileged

# Inspect
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

# Scan image for vulnerabilities
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

### Cleanup

```bash
docker rm -f db app web hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
```

---

## 🔑 Terraform Commands

### Install Terraform

```bash
# macOS
brew tap hashicorp/tap
brew install hashicorp/tap/terraform

# Windows
winget install Hashicorp.Terraform

# Verify
terraform --version
```

### Terraform Workflow

```bash
# Initialize
terraform init

# Format and validate
terraform fmt
terraform validate

# Plan (review changes)
terraform plan

# Apply
terraform apply -auto-approve

# Destroy
terraform destroy -auto-approve
```

### Terraform HCL Example (main.tf)

```hcl
provider "aws" {
  access_key = "test"
  secret_key = "test"
  region = "us-east-1"
  
  endpoints {
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
  }
  
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_requesting_account_id = true
}

resource "aws_iam_group" "admins" {
  name = "Admins"
}

resource "aws_iam_user" "cloud_admin" {
  name = "CloudAdmin_YOURNAME"
}

resource "aws_iam_group_policy_attachment" "admin_policy" {
  group = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_group_membership" "cloud_admin_membership" {
  user = aws_iam_user.cloud_admin.name
  groups = [aws_iam_group.admins.name]
}
```

---

## 🧹 Final Cleanup

```bash
# Stop LocalStack
docker stop localstack && docker rm localstack

# Remove all temporary files
rm -f *.txt *.pem *.enc *.rsa *.sig *.json *.yaml *.log
rm -f rec*.txt datakey.* tampered.txt

# Delete Kubernetes cluster
kind delete cluster --name ccse-lab1
kind delete cluster --name ccse-lab2
```

---

## 📋 Evidence Checklist

| Section | Command | What to Capture |
|---------|---------|-----------------|
| Environment | `aws $EP sts get-caller-identity` | Identity output |
| IAM | `aws $EP iam get-group --group-name Admins` | Group membership |
| IAM | `aws $EP iam list-attached-user-policies --user-name Analyst_YOURNAME` | Read-only policy |
| RBAC | `kubectl auth can-i list pods -n dev --as=$SA` | YES (allowed) |
| RBAC | `kubectl auth can-i delete pods -n dev --as=$SA` | NO (denied) |
| RBAC | `kubectl auth can-i list pods -n prod --as=$SA` | NO (denied) |
| Network Policy | Probe results | Before (200) vs After (timeout) |
| Pod Security | `kubectl apply -f privileged-pod.yaml` | Rejection message |
| Encryption | `openssl dgst -sha256 -verify public.pem -signature record.sig record.txt` | Verified OK |
| KMS | Failed decrypt after key erasure | Error message |
| Logging | `aws $EP logs get-log-events` | Centralized logs |
| Logging | `sha256sum -c evidence.sha256` | Hash verification |
| S3 | `aws $EP s3api get-public-access-block --bucket $BUCKET` | Block Public Access config |
| S3 | `aws $EP s3api head-object` | SSE-KMS encryption |
| S3 | Version listing | Delete marker + recovered data |

---

## 📚 Quick Reference Card

### Common Variables
```bash
export EP='--endpoint-url=http://localhost:4566'
export BUCKET=mii-patient-records-$RANDOM
export KEY_ID=$(aws $EP kms create-key --query 'KeyMetadata.KeyId' --output text)
```

### Service Ports
| Service | Port |
|---------|------|
| LocalStack | 4566 |
| HTTPS (TLS) | 8443 |
| Kubernetes API | 6443 |

### Useful One-liners
```bash
# List all S3 buckets
aws $EP s3 ls

# List all KMS keys
aws $EP kms list-keys

# List all IAM users
aws $EP iam list-users

# List all Kubernetes namespaces
kubectl get namespaces

# List all network policies
kubectl get networkpolicy -A

# Get all pods in all namespaces
kubectl get pods -A
```

---

**Good luck with your skill-based assessment!** 🎯
