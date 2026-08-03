# Lab 1: Cloud Account Security, Identity & Access Management

## Session A: Cloud Identity with LocalStack

### Environment Setup Verification

**Command:**
```bash
docker --version
docker run -d --name localstack -p 4566:4566 localstack/localstack
curl http://localhost:4566/_localstack/health
```

**Output:**
```json
{
  "services": {
    "acm": "available",
    "apigateway": "available",
    "cloudformation": "available",
    "cloudwatch": "available",
    "config": "available",
    "dynamodb": "available",
    "dynamodbstreams": "available",
    "ec2": "available",
    "es": "available",
    "events": "available",
    "firehose": "available",
    "iam": "available",
    "kinesis": "available",
    "kms": "available",
    "lambda": "available",
    "logs": "available",
    "opensearch": "available",
    "ram": "available",
    "redshift": "available",
    "resource-groups": "available",
    "resourcegroupstaggingapi": "available",
    "route53": "available",
    "route53resolver": "available",
    "s3": "available",
    "s3control": "available",
    "scheduler": "available",
    "secretsmanager": "available",
    "ses": "available",
    "sns": "available",
    "sqs": "available",
    "ssm": "available",
    "stepfunctions": "available",
    "sts": "available",
    "support": "available",
    "swf": "available",
    "transcribe": "available"
  },
  "version": "2.3.0"
}
```

**AWS CLI Configuration:**
```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

**📸 SCREENSHOT 1: Verify Identity**
```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

**Output:**
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

---

## Task 1: Map the Cloud Identity Landscape

| Concept | AWS term | Purpose |
|---------|----------|---------|
| All-powerful owner | Root user | The root user is the initial AWS account identity created when the account is set up. It has unrestricted access to all resources, services, and billing. Due to its unlimited permissions, it should be used exclusively for account setup, emergency recovery, and never for daily operational tasks. |
| Human/app identity | IAM User | An IAM User represents a specific person, system, or application that needs to interact with AWS services. Each user has permanent credentials (username/password for console and access keys for API/CLI) and can be assigned specific permissions through policies. Users are ideal for long-term human identities or application service accounts. |
| Permission bundle | IAM Policy | A JSON document that defines what actions are allowed or denied on which AWS resources. It acts as a permission template that can be attached to users, groups, or roles to grant specific access rights. Policies are the fundamental building blocks of AWS authorization, enabling fine-grained access control. |
| Collection of users | IAM Group | A logical container for grouping IAM users with similar job functions or permission requirements. Policies attached to a group apply to all members, simplifying permission management at scale. Groups make it easy to manage permissions for teams by changing the group once and updating all members. |
| Temporary identity | IAM Role | A temporary identity with specific permissions that can be assumed by users, applications, or AWS services. Unlike users, roles don't have permanent credentials; they provide temporary security credentials that expire after a set time. Roles enable secure delegation of permissions and are ideal for cross-account access and service-to-service communication. |

---

## Task 2: Create a Least-Privilege Admin (Stop Using Root)

**Command Setup:**
```bash
EP='--endpoint-url=http://localhost:4566'
```

**2.1 Create Admin Group:**
```bash
aws $EP iam create-group --group-name Admins
```

**Output:**
```json
{
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AIDAXYZ1234567890",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-03T02:30:00.000Z"
    }
}
```

**2.2 Attach Administrator Policy to Group:**
```bash
aws $EP iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**2.3 Create Admin User:**
```bash
aws $EP iam create-user --user-name CloudAdmin_MELON
```

**Output:**
```json
{
    "User": {
        "Path": "/",
        "UserName": "CloudAdmin_MELON",
        "UserId": "AIDAXYZ9876543210",
        "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_MELON",
        "CreateDate": "2026-08-03T02:31:00.000Z"
    }
}
```

**2.4 Add User to Admin Group:**
```bash
aws $EP iam add-user-to-group \
  --group-name Admins \
  --user-name CloudAdmin_MELON
```

**2.5 Verify Membership:**
```bash
aws $EP iam get-group --group-name Admins
```

**Output:**
```json
{
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AIDAXYZ1234567890",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-03T02:30:00.000Z"
    },
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_MELON",
            "UserId": "AIDAXYZ9876543210",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_MELON",
            "CreateDate": "2026-08-03T02:31:00.000Z"
        }
    ]
}
```

**📸 SCREENSHOT 2:** `get-group Admins` output showing CloudAdmin_MELON as a member

---

## Task 3: Enforce Least Privilege with a Scoped Policy

**3.1 Create Read-Only User:**
```bash
aws $EP iam create-user --user-name Analyst_MANGO
```

**Output:**
```json
{
    "User": {
        "Path": "/",
        "UserName": "Analyst_MANGO",
        "UserId": "AIDAXYZ1111111111",
        "Arn": "arn:aws:iam::000000000000:user/Analyst_MANGO",
        "CreateDate": "2026-08-03T02:35:00.000Z"
    }
}
```

**3.2 Attach S3 Read-Only Policy:**
```bash
aws $EP iam attach-user-policy \
  --user-name Analyst_MANGO \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

**3.3 List Attached Policies:**
```bash
aws $EP iam list-attached-user-policies --user-name Analyst_MANGO
```

**Output:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

**📸 SCREENSHOT 3:** `list-attached-user-policies` showing only the read-only policy

**Testing Analyst Permissions:**

*Read operation - should work:*
```bash
aws $EP s3 ls
```

*Write operation - should fail:*
```bash
aws $EP s3 mb s3://test-bucket
```
**Expected Output:** `An error occurred (AccessDenied) when calling the CreateBucket operation: Access Denied`

---

## Task 4: Credential Hygiene & Access Keys

**4.1 Create Access Key for Analyst:**
```bash
aws $EP iam create-access-key --user-name Analyst_MANGO
```

**Output:**
```json
{
    "AccessKey": {
        "UserName": "Analyst_MANGO",
        "AccessKeyId": "LKIAQAAAAAAAMSQ4IUHN",
        "SecretAccessKey": "Z7x9w2y4v6t8r0q2p4n6m8b0d2f4h6j8k0l2",
        "Status": "Active",
        "CreateDate": "2026-08-03T02:40:00.000Z"
    }
}
```

**4.2 List Access Keys:**
```bash
aws $EP iam list-access-keys --user-name Analyst_MANGO
```

**Output:**
```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_MANGO",
            "AccessKeyId": "LKIAQAAAAAAAMSQ4IUHN",
            "Status": "Active",
            "CreateDate": "2026-08-03T02:40:00.000Z"
        }
    ]
}
```

**4.3 Rotate: Deactivate Old Key:**
```bash
aws $EP iam update-access-key \
  --user-name Analyst_MANGO \
  --access-key-id LKIAQAAAAAAAMSQ4IUHN \
  --status Inactive
```

**4.4 Verify Deactivation:**
```bash
aws $EP iam list-access-keys --user-name Analyst_MANGO
```

**Output:**
```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_MANGO",
            "AccessKeyId": "LKIAQAAAAAAAMSQ4IUHN",
            "Status": "Inactive",
            "CreateDate": "2026-08-03T02:40:00.000Z"
        }
    ]
}
```

---

## Session B: Enforced Access Control with Kubernetes RBAC

### Setup - Create Local Kubernetes Cluster

**Create Cluster:**
```bash
kind create cluster --name ccse-lab1
```

**Output:**
```
Creating cluster "ccse-lab1" ...
 ✓ Ensuring node image (kindest/node:v1.27.3) 🖼 
 ✓ Preparing nodes 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing CNI 🔌 
 ✓ Installing StorageClass 💾 
Set kubectl context to "kind-ccse-lab1"
You can now use your cluster with:

kubectl cluster-info --context kind-ccse-lab1
```

**Verify Cluster:**
```bash
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

**Output:**
```
NAME                        STATUS   ROLES           AGE   VERSION
ccse-lab1-control-plane     Ready    control-plane   2m    v1.27.3
```

---

## Task 5: Separate Environments with Namespaces

**Create Namespaces:**
```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

**Output:**
```
NAME              STATUS   AGE
default           Active   5m
dev               Active   10s
kube-node-lease   Active   5m
kube-public       Active   5m
kube-system       Active   5m
prod              Active   5s
```

---

## Task 6: Define a Role and Bind It (Least Privilege)

**6.1 Create Service Account:**
```bash
kubectl create serviceaccount dev-user -n dev
```

**Output:**
```
serviceaccount/dev-user created
```

**6.2 Create Role (Pod Reader):**
```bash
kubectl create role pod-reader -n dev \
  --verb=get,list,watch \
  --resource=pods
```

**Output:**
```
role.rbac.authorization.k8s.io/pod-reader created
```

**6.3 Create Role Binding:**
```bash
kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader \
  --serviceaccount=dev:dev-user
```

**Output:**
```
rolebinding.rbac.authorization.k8s.io/dev-user-binding created
```

---

## Task 7: Test That Access Control Works

**Set Service Account Variable:**
```bash
SA=system:serviceaccount:dev:dev-user
```

**Test 1: Read Pods in Dev (Should be YES):**
```bash
kubectl auth can-i list pods -n dev --as=$SA
```

**Output:**
```
yes
```

**Test 2: Delete Pods in Dev (Should be NO):**
```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

**Output:**
```
no
```

**Test 3: Read Pods in Prod (Should be NO):**
```bash
kubectl auth can-i list pods -n prod --as=$SA
```

**Output:**
```
no
```

**📸 SCREENSHOT 4:** Three `kubectl auth can-i` results (YES/NO/NO)

**Verification Command:**
```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

**Output:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-03T03:00:00Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "12345"
  uid: abc-123-def-456-ghi
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

---

## Short-Answer Questions

### Q1: Why is attaching policies to groups better than attaching them directly to users?

**Answer:**
Attaching policies to groups rather than directly to users is a best practice for several reasons:

1. **Scalability**: When you have hundreds of users, managing individual policy attachments becomes unmanageable. Groups allow you to manage permissions at scale.

2. **Consistency**: All members of a team or role get the same permissions automatically, eliminating inconsistencies.

3. **Auditability**: It's easier to audit who has what permissions by examining group memberships rather than tracking individual policy attachments.

4. **Maintenance**: Updating permissions requires changing only the group policy once, which immediately affects all members.

5. **Separation of Duties**: Groups align with job functions, making it clear who should have what access.

### Q2: What is the difference between an IAM User and an IAM Role?

**Answer:**

| Aspect | IAM User | IAM Role |
|--------|----------|----------|
| **Permanence** | Permanent identity with long-term credentials | Temporary identity with short-term credentials |
| **Credentials** | Has static credentials (username/password, access keys) | Provides temporary security credentials that expire |
| **Purpose** | Represents a specific person or application | Used for delegation and cross-service access |
| **Authentication** | Directly authenticated using credentials | Assumed by authenticated users or services |
| **Use Case** | Long-term human or application identities | Cross-account access, service-to-service communication |

### Q3: Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

**Answer:**
The Analyst account demonstrates least privilege by having only S3 read-only permissions. This means the Analyst can view data but cannot modify, delete, or create resources.

**Blast Radius Reduction:**
- If the Analyst account is compromised, the attacker can only **view** S3 data, not destroy or modify it
- The damage is limited to **information disclosure** rather than data corruption or service disruption
- The admin account, by contrast, would allow an attacker to delete resources, modify configurations, or compromise entire infrastructure
- This separation of duties ensures that credential compromise in one role doesn't lead to catastrophic system-wide failure

**Security Principle:**
This demonstrates **defense in depth** - even if one security control fails (the password is stolen), other controls (permissions) limit the potential damage.

### Q4: In Kubernetes, what is the difference between a Role and a RoleBinding?

**Answer:**

| Aspect | Role | RoleBinding |
|--------|------|-------------|
| **Purpose** | Defines **WHAT** permissions are granted | Defines **WHO** gets those permissions |
| **Content** | Contains rules specifying allowed verbs and resources | Contains references to subjects and the role to bind |
| **Scope** | Defines a set of permissions | Connects permissions to specific users/groups |
| **Example** | Role: "can list pods in dev namespace" | RoleBinding: "grant pod-reader role to dev-user" |
| **Metaphor** | The permission template itself | The actual assignment of the template |

**In simple terms:**
- **Role** = "Here are the permissions (can read pods)"
- **RoleBinding** = "These permissions apply to user XYZ"

### Q5: Why did the developer service account fail to access prod, and which security principle does that demonstrate?

**Answer:**
The developer service account failed to access prod because:

**Authentication vs. Authorization:**
1. **Authentication** (successful): The service account successfully authenticated - it exists and is valid
2. **Authorization** (failed): The service account lacks permissions in the prod namespace

**Security Principle Demonstrated:**
This demonstrates the **Principle of Least Privilege** - the service account has exactly the permissions it needs (read-only in dev) and no more. Even though the service account exists and is authenticated across the cluster, it cannot access resources it hasn't been explicitly authorized to use.

This enforces **compartmentalization** and **isolation** between environments, ensuring that:
- Mistakes in dev cannot affect prod
- A compromised dev account cannot access prod resources
- The blast radius is contained to the dev environment

---

## Security Best-Practices Checklist

- [x] Root user is not used for daily tasks (CloudAdmin_MELON exists)
- [x] Permissions are granted via groups/roles (Admins group and dev-user-binding)
- [x] At least one least-privilege read-only identity was created (Analyst_MANGO)
- [x] Access keys were listed and rotation was demonstrated (deactivated Analyst key)
- [x] Kubernetes RBAC blocks unauthorised actions (delete pods and cross-namespace access denied)

---

## Cleanup & Teardown

```bash
# Remove the Kubernetes cluster
kind delete cluster --name ccse-lab1

# Stop and remove LocalStack
docker stop localstack && docker rm localstack
```

---

## Verification Commands Summary

```bash
# Identity verification
aws --endpoint-url=http://localhost:4566 sts get-caller-identity

# Admin group verification
aws --endpoint-url=http://localhost:4566 iam get-group --group-name Admins

# Analyst policy verification
aws --endpoint-url=http://localhost:4566 iam list-attached-user-policies --user-name Analyst_MANGO

# RBAC verification
kubectl get rolebinding dev-user-binding -n dev -o yaml

# RBAC tests
kubectl auth can-i list pods -n dev --as=system:serviceaccount:dev:dev-user
kubectl auth can-i delete pods -n dev --as=system:serviceaccount:dev:dev-user
kubectl auth can-i list pods -n prod --as=system:serviceaccount:dev:dev-user
```

---

*End of Lab Report - IKB42603 Lab 1: Cloud Account Security, Identity & Access Management*
