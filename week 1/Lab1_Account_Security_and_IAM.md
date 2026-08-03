# Lab 1: Cloud Account Security, Identity & Access Management

## Course Information
- **Course Name:** IKB42603 Cloud Computing Security Essentials
- **Instructor:** MISS NOR ADANI KAMAL MOHAMAD NASIR 
- **Student Name:** NUREEN FARHAH BINTI AZMAL
- **Student ID:** 52215125191
- **Class:** B03
- **Environment:** Kali Linux, Docker, LocalStack, AWS CLI, Kubernetes (kind) and kubectl
- **Date:** 3 August 2026

---

## Lab Summary and Objectives

### Lab Summary

This laboratory exercise provided a comprehensive, hands-on exploration of identity and access management (IAM) principles across two distinct cloud-native environments: **LocalStack** (simulating AWS IAM) and **Kubernetes RBAC** (Role-Based Access Control). The lab was structured to demonstrate real-world security practices through sequential tasks that built upon one another, progressing from fundamental IAM concepts to practical implementation and verification.

The LocalStack component focused on AWS IAM operations, where participants created and managed users, groups, policies, and access keys within a local cloud simulation environment. This approach eliminated the risks associated with live AWS accounts while maintaining functional parity with actual AWS IAM services. Through a series of structured tasks, the lab demonstrated how to implement least privilege access, establish administrative boundaries, and maintain proper credential hygiene.

The Kubernetes RBAC component shifted focus to container orchestration security, where participants created namespaces to logically separate environments, defined service accounts for identity management, and implemented granular permission controls through Roles and RoleBindings. This segment emphasized how authorization policies can be scoped to specific namespaces and resources, preventing unauthorized access across different application environments.

Throughout the lab, emphasis was placed on **defense-in-depth** principles, particularly:
- **Least privilege access** – granting only the minimum permissions required
- **Separation of duties** – distinguishing between administrative and operational roles
- **Credential lifecycle management** – creating, verifying, and deactivating access credentials
- **Environment isolation** – using namespaces and policies to prevent lateral movement

The practical exercises culminated in verification steps that validated the effectiveness of implemented security controls, demonstrating how proper IAM configurations can significantly reduce the blast radius of potential security incidents.

### Lab Objectives

#### Primary Objectives

**1. Apply Least Privilege Principles in IAM Configuration**
- Create role-specific users and groups with tailored permissions
- Implement scoped policies that limit access to required actions
- Demonstrate administrative vs. read-only access boundaries

**2. Implement Identity Governance Structures**
- Establish group-based permission management for administrative access
- Differentiate between identity types (users, groups, roles, service accounts)
- Apply namespace-based isolation in Kubernetes environments

**3. Practice Secure Credential Management**
- Generate and manage access keys for programmatic access
- Implement credential rotation through deactivation procedures
- Verify credential status and enforce security controls

**4. Configure and Test RBAC Authorization**
- Create service accounts with specific permissions
- Define Roles with granular verb and resource restrictions
- Establish RoleBindings to associate identities with permissions
- Test authorization boundaries using verification commands

#### Technical Competencies

Upon completing this lab, participants will be able to:
- Navigate AWS CLI commands for IAM operations using LocalStack endpoints
- Create and manage Kubernetes resources including namespaces, service accounts, roles, and role bindings
- Verify permissions using appropriate CLI tools (`aws` and `kubectl`)
- Document security configurations and demonstrate evidence of successful implementation

#### Security-Focused Outcomes

- Understand the impact of identity compromise and how proper IAM reduces blast radius
- Recognize the importance of separating duties between administrative and operational users
- Appreciate the value of environment isolation in preventing unauthorized access
- Develop habits of credential hygiene and regular permission reviews
- Build foundational knowledge for advanced IAM and RBAC configurations

#### Connection to Course Goals

This lab serves as the foundation for understanding cloud security's first line of defense: **who can access what**. The skills developed here directly support the course's broader objectives of preparing students to:
- Secure cloud-native applications and infrastructure
- Implement compliant access control frameworks
- Respond effectively to identity-based security threats
- Design systems with security as a foundational principle rather than an afterthought
---

## Session A: Cloud Identity with LocalStack

### Environment Setup Verification

Before performing any IAM configuration, the LocalStack environment was set up and verified. Docker was used to run LocalStack, providing a local AWS cloud simulation. The `docker --version` command confirms that Docker is installed and ready. The LocalStack container was then started in detached mode, exposing port 4566 for API communication. The health check verified that all services including IAM, S3, and STS are running properly.

**Command:**
```bash
docker --version
docker run -d --name localstack -p 4566:4566 localstack/localstack
curl http://localhost:4566/_localstack/health
```

**Output:**

<img width="575" height="112" alt="docker version" src="https://github.com/user-attachments/assets/caf98f7d-85ed-484d-a68e-3202b58009e0" />
<img width="594" height="443" alt="docker run" src="https://github.com/user-attachments/assets/ab27efb7-5cd6-40c1-8886-ecfe4574c075" />
<img width="974" height="266" alt="health check" src="https://github.com/user-attachments/assets/a4121f97-2caf-43cb-a1af-86a487080862" />

**Figure 1.0:** Docker version verification, LocalStack container creation, and service health check.

**AWS CLI Configuration:**

The AWS CLI was configured with test credentials to communicate with the LocalStack endpoint. Since LocalStack uses dummy credentials, the values `test` were used for both access key and secret key. The region was set to `us-east-1` to match typical AWS configurations.

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

**Identity Verification:**

The `sts get-caller-identity` command was executed to verify that the AWS CLI was successfully connected to the LocalStack environment. The output displays the default LocalStack account ID (`000000000000`), confirming that all subsequent IAM operations will be performed locally rather than on the real AWS cloud.

```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

**Output:**

<img width="972" height="419" alt="STS verification" src="https://github.com/user-attachments/assets/a24d662e-74eb-4a99-8782-ec1887dfdd42" />

**Figure 1.1:** Verification of the AWS CLI connection to the LocalStack IAM environment using the `sts get-caller-identity` command.

---

## Task 1: Map the Cloud Identity Landscape

Before configuring access, it is important to distinguish the main identity concepts used by AWS. Each concept has a different purpose in controlling who can access resources and what actions they may perform.

| Concept | AWS Term | Purpose |
|---|---|---|
| All-powerful owner | Root user | The root user is the initial AWS account identity created when the account is set up. It has unrestricted access to all resources, services, and billing. Due to its unlimited permissions, it should be used exclusively for account setup, emergency recovery, and never for daily operational tasks. |
| Human/app identity | IAM User | An IAM User represents a specific person, system, or application that needs to interact with AWS services. Each user has permanent credentials (username/password for console and access keys for API/CLI) and can be assigned specific permissions through policies. Users are ideal for long-term human identities or application service accounts. |
| Permission bundle | IAM Policy | A JSON document that defines what actions are allowed or denied on which AWS resources. It acts as a permission template that can be attached to users, groups, or roles to grant specific access rights. Policies are the fundamental building blocks of AWS authorization, enabling fine-grained access control. |
| Collection of users | IAM Group | A logical container for grouping IAM users with similar job functions or permission requirements. Policies attached to a group apply to all members, simplifying permission management at scale. Groups make it easy to manage permissions for teams by changing the group once and updating all members. |
| Temporary identity | IAM Role | A temporary identity with specific permissions that can be assumed by users, applications, or AWS services. Unlike users, roles don't have permanent credentials; they provide temporary security credentials that expire after a set time. Roles enable secure delegation of permissions and are ideal for cross-account access and service-to-service communication. |

---

## Task 2: Create a Least-Privilege Admin

Rather than using the root identity for routine administration, a named administrator was created. Administrative access was assigned through a group so that permissions could be centrally managed.

**Command Setup:**

An environment variable `EP` was set to simplify commands and avoid repeating the endpoint URL for each AWS CLI operation.

```bash
EP='--endpoint-url=http://localhost:4566'
```

### Step 2.1: Create the Admins Group

To implement centralized permission management, an IAM group named `Admins` was created in the LocalStack environment. This group will serve as a container for administrative users, allowing permissions to be managed at the group level.

```bash
aws $EP iam create-group --group-name Admins
```

**Output:**

<img width="487" height="203" alt="create admins group" src="https://github.com/user-attachments/assets/04d64a46-ed8c-4ab0-b26e-e5000b2d17ab" />

**Figure 2.1:** Creation of the `Admins` IAM group in the LocalStack environment.

### Step 2.2: Attach Administrator Policy to Group

After the group was successfully created, the managed `AdministratorAccess` policy was attached to it. Assigning permissions through a group allows administrator privileges to be inherited by group members instead of attaching policies directly to individual users. This approach simplifies permission management and follows AWS IAM best practices.

```bash
aws $EP iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Step 2.3: Create a Personal Administrator Account

A dedicated IAM user named `CloudAdmin_MELON` was created to perform administrative tasks instead of using the root account. Creating a separate administrator account improves accountability and follows the security best practice of avoiding the use of the root identity for routine administration.

```bash
aws $EP iam create-user --user-name CloudAdmin_MELON
```

**Output:**

<img width="442" height="164" alt="create admin user" src="https://github.com/user-attachments/assets/08047a47-2536-4da5-b3d8-817329b144af" />

**Figure 2.2:** Successful creation of the `CloudAdmin_MELON` IAM user in the LocalStack environment.

### Step 2.4: Add the Administrator User to the Admins Group

After creating the personal administrator account, the user `CloudAdmin_MELON` was added to the `Admins` group. This allows the user to inherit the permissions assigned to the group instead of attaching administrator policies directly to the user account.

```bash
aws $EP iam add-user-to-group \
  --group-name Admins \
  --user-name CloudAdmin_MELON
```

<img width="365" height="61" alt="add user to group" src="https://github.com/user-attachments/assets/d7f12a5f-aa78-4785-a7f4-88ebddb86196" />

**Figure 2.3:** Command used to add the `CloudAdmin_MELON` user to the `Admins` IAM group.

### Step 2.5: Verify Administrator Group Membership

The `get-group` command was executed to verify that the `CloudAdmin_MELON` user had been successfully added to the `Admins` group. The output displays both the group information and the user details, confirming that the administrator account is now a member of the group.

```bash
aws $EP iam get-group --group-name Admins
```

**Output:**

<img width="459" height="271" alt="verify group membership" src="https://github.com/user-attachments/assets/73db4018-a4e7-4daf-8059-bc77a28bdcac" />

**Figure 2.4:** Verification that the `CloudAdmin_MELON` user is a member of the `Admins` IAM group.

---

## Task 3: Enforce Least Privilege with a Scoped Policy

A separate analyst identity was created for work that does not require administrative control. Giving this user only read access illustrates how permissions can be matched to a job function.

### Step 3.1: Create the Analyst User

A dedicated IAM user named `Analyst_MANGO` was created to represent an analyst account with limited access. This user is intended to perform tasks that do not require administrative privileges, supporting the principle of least privilege by separating administrative and non-administrative responsibilities.

```bash
aws $EP iam create-user --user-name Analyst_MANGO
```

**Output:**

<img width="499" height="183" alt="create analyst user" src="https://github.com/user-attachments/assets/b1c45b8b-06c2-46d5-88c5-9098ac64ee34" />

**Figure 3.1:** Successful creation of the `Analyst_MANGO` IAM user in the LocalStack environment.

### Step 3.2: Attach the AmazonS3ReadOnlyAccess Policy

To enforce the principle of least privilege, the `AmazonS3ReadOnlyAccess` managed policy was attached to the `Analyst_MANGO` user. This policy grants read-only access to Amazon S3 resources, allowing the user to view information without creating, modifying or deleting any objects. Assigning only the required permissions helps reduce potential security risks.

```bash
aws $EP iam attach-user-policy \
  --user-name Analyst_MANGO \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step 3.3: Verify the Attached Policy

The attached policies for the `Analyst_MANGO` user were verified using the AWS CLI. The output shows that only the `AmazonS3ReadOnlyAccess` managed policy is assigned to the user. This confirms that the analyst account has read-only permissions and does not possess unnecessary administrative privileges.

```bash
aws $EP iam list-attached-user-policies --user-name Analyst_MANGO
```

**Output:**

<img width="452" height="63" alt="list policies step 1" src="https://github.com/user-attachments/assets/f7843f90-80ef-4cdc-942a-f6250c329354" />
<img width="405" height="118" alt="list policies step 2" src="https://github.com/user-attachments/assets/e6990e6d-95f3-40df-bb6f-5df257b700ab" />

**Figure 3.2:** Verification that the `AmazonS3ReadOnlyAccess` managed policy is attached to the `Analyst_MANGO` IAM user.

### Least-Privilege Explanation

The `Analyst_MANGO` identity is limited to viewing S3 information and objects permitted by the managed policy. If its credentials were compromised, an attacker would not gain administrator privileges through this account. The identity could not use IAM administration capabilities to create privileged users or change policies, and its read-only scope would prevent write or delete operations in S3. Restricting the account in this way reduces the possible impact, or blast radius, of a credential compromise.

### Testing Analyst Permissions

To verify the least privilege configuration, both read and write operations were tested with the `Analyst_MANGO` account.

**Read Operation - Should Succeed:**

The `s3 ls` command lists existing S3 buckets. Since read access is allowed, this operation should complete successfully (possibly showing no buckets in an empty LocalStack environment).

```bash
aws $EP s3 ls
```
**Expected Output:** Empty list (no buckets found)

**Write Operation - Should Fail:**

The `s3 mb` command attempts to create a new bucket. Since the analyst account only has read permissions, this operation should be denied.

```bash
aws $EP s3 mb s3://test-bucket
```
**Expected Output:** `An error occurred (AccessDenied) when calling the CreateBucket operation: Access Denied`

---

## Task 4: Credential Hygiene & Access Keys

Access keys are long-term credentials and therefore require careful handling. This task demonstrated their creation, inspection and deactivation as part of a basic credential-rotation process.

### Step 4.1: Create an Access Key

An access key was generated for the `Analyst_MANGO` IAM user to enable programmatic access to cloud services. The generated credentials consist of an Access Key ID and a Secret Access Key, which are used to authenticate API requests. In practice, these credentials should be protected and never exposed in public repositories or shared with unauthorized individuals.

```bash
aws $EP iam create-access-key --user-name Analyst_MANGO
```

**Output:**

<img width="855" height="266" alt="create access key" src="https://github.com/user-attachments/assets/c3552392-4b79-408e-8c19-86eba488c44a" />

**Figure 4.1:** Successful creation of an access key for the `Analyst_MANGO` IAM user.

### Step 4.2: List Access Keys

The access keys associated with the `Analyst_MANGO` account were listed to verify that the newly created credentials were successfully registered. The output displays the Access Key ID, user name, creation date and current status. The status `Active` confirms that the access key is valid and can be used for programmatic authentication.

```bash
aws $EP iam list-access-keys --user-name Analyst_MANGO
```

**Output:**

<img width="850" height="302" alt="list access keys" src="https://github.com/user-attachments/assets/38b2ffcd-42a6-495e-9fd6-7c782bb47340" />

**Figure 4.2:** Verification of the active access key assigned to the `Analyst_MANGO` IAM user.

### Step 4.3: Deactivate the Access Key

To demonstrate credential hygiene, the access key associated with the `Analyst_MANGO` account was deactivated using the AWS CLI. The command updates the key status to `Inactive`, ensuring the credentials can no longer be used for authentication while still remaining in the account for management purposes.

```bash
aws $EP iam update-access-key \
  --user-name Analyst_MANGO \
  --access-key-id <ACCESS KEY ID> \
  --status Inactive
```

**Output:**

<img width="752" height="85" alt="deactivate access key" src="https://github.com/user-attachments/assets/74a03577-d3bb-4511-90e6-d4f389e42dd7" />

**Figure 4.3:** Deactivation of the access key for the `Analyst_MANGO` IAM user.

---

## Session B: Enforced Access Control with Kubernetes RBAC

### Setup: Create a Local Kubernetes Cluster

A new Kubernetes cluster named `ccse-lab1` was created using **kind (Kubernetes in Docker)** to provide an isolated environment for testing Kubernetes Role-Based Access Control (RBAC). After the cluster was successfully created, the cluster status was verified using `kubectl cluster-info` and `kubectl get nodes`.

**Create Cluster:**

```bash
kind create cluster --name ccse-lab1
```

**Output:**

<img width="861" height="348" alt="kind cluster creation" src="https://github.com/user-attachments/assets/85298633-d1fe-40db-a639-484308a956b3" />

**Figure 5.0:** Creation of the `ccse-lab1` Kubernetes cluster using kind.

**Verify Cluster:**

The cluster status was verified using cluster-info and node status commands. The output confirms that the Kubernetes control plane is running correctly and that the control-plane node is in the **Ready** state.

```bash
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

**Output:**

<img width="974" height="301" alt="cluster verification" src="https://github.com/user-attachments/assets/0ac90c54-9173-45de-b1cc-8d9538ddf716" />

**Figure 5.1:** Verification of the Kubernetes cluster status showing the control plane and node readiness.

---

## Task 5: Separate Environments with Namespaces

Namespaces were created to logically separate resources within the Kubernetes cluster. In this task, two namespaces named `dev` and `prod` were created to represent the development and production environments. After creating the namespaces, the cluster was verified to ensure that both environments were successfully added.

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

**Output:**

<img width="669" height="570" alt="create namespaces" src="https://github.com/user-attachments/assets/8d0f4fca-90b5-4b13-8732-6234352a2c32" />

**Figure 5.2:** Creation and verification of the `dev` and `prod` namespaces in the Kubernetes cluster.

---

## Task 6: Define a Role and Bind It

Kubernetes RBAC separates the description of permissions from the assignment of those permissions. A service account was created first, followed by a namespaced Role and a RoleBinding.

### Step 6.1: Create a Service Account

A Kubernetes service account named `dev-user` was created in the `dev` namespace to represent a developer identity. This service account will be used in the following RBAC configuration to demonstrate how permissions can be assigned to non-human identities within a specific namespace.

```bash
kubectl create serviceaccount dev-user -n dev
```

**Output:**

<img width="897" height="166" alt="create service account" src="https://github.com/user-attachments/assets/e4aef853-8971-42b4-a3b9-f5f6e000aa2d" />

**Figure 6.1:** Successful creation of the `dev-user` service account in the `dev` namespace.

### Step 6.2: Create a Role

A Kubernetes role named `pod-reader` was created in the `dev` namespace to grant read-only access to pod resources. The role allows users or service accounts to perform the `get`, `list`, and `watch` operations without permitting any modifications. This configuration follows the principle of least privilege by granting only the permissions required to perform read-only tasks.

```bash
kubectl create role pod-reader -n dev \
  --verb=get,list,watch \
  --resource=pods
```

**Output:**

<img width="859" height="172" alt="create role" src="https://github.com/user-attachments/assets/13bbfcbf-b7b1-4220-b919-657b9c5a5ac7" />

**Figure 6.2:** Successful creation of the `pod-reader` role in the `dev` namespace.

### Step 6.3: Create a RoleBinding

A RoleBinding named `dev-user-binding` was created in the `dev` namespace to associate the `pod-reader` role with the `dev-user` service account. This binding grants the service account the permissions defined in the role, allowing it to perform only the authorized read-only operations on pods within the `dev` namespace.

```bash
kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader \
  --serviceaccount=dev:dev-user
```

**Output:**

<img width="930" height="143" alt="create rolebinding" src="https://github.com/user-attachments/assets/1fa84469-6070-4789-9c3a-57a228cc8d98" />

**Figure 6.3:** Successful creation of the `dev-user-binding` RoleBinding in the `dev` namespace.

---

## Task 7: Test That Access Control Works

The permissions assigned to the `dev-user` service account were verified using the `kubectl auth can-i` command. Three authorization checks were performed to validate the RBAC configuration.

**Set Service Account Variable:**

```bash
SA=system:serviceaccount:dev:dev-user
```

### Test 1: Read Pods in Dev (Should be YES)

The service account can list pods within the `dev` namespace, confirming that the read-only permission granted by the `pod-reader` role is working correctly.

```bash
kubectl auth can-i list pods -n dev --as=$SA
```

**Output:**

<img width="559" height="229" alt="test list pods dev" src="https://github.com/user-attachments/assets/8db2b93d-8769-48f3-b57c-7a0962d4b1da" />

**Figure 7.1:** Verification that the `dev-user` service account can list pods in the `dev` namespace.

### Test 2: Delete Pods in Dev (Should be NO)

The service account cannot delete pods within the `dev` namespace, confirming that the role does not grant any write or delete permissions.

```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

**Output:**

<img width="758" height="181" alt="test delete pods dev" src="https://github.com/user-attachments/assets/b3371474-5dca-48f8-bd11-42d84b26fcf5" />

**Figure 7.2:** Verification that the `dev-user` service account cannot delete pods in the `dev` namespace.

### Test 3: Read Pods in Prod (Should be NO)

The service account cannot access pods in the `prod` namespace, confirming that permissions are scoped only to the `dev` namespace where the Role and RoleBinding were created.

```bash
kubectl auth can-i list pods -n prod --as=$SA
```

**Output:**

<img width="763" height="163" alt="test list pods prod" src="https://github.com/user-attachments/assets/032a6493-0543-42e8-af47-1cfeff1581a5" />

**Figure 7.3:** Verification that the `dev-user` service account cannot list pods in the `prod` namespace.

### Verification Command

The RoleBinding configuration was reviewed in YAML format to verify that the RBAC policy had been applied successfully. This verification ensures that the correct role is linked to the intended service account within the appropriate namespace.

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

**Output:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-03T..."
  name: dev-user-binding
  namespace: dev
  ...
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

<img width="616" height="369" alt="verify rolebinding yaml" src="https://github.com/user-attachments/assets/b840f74f-1535-4d1d-aa22-408d71ee1541" />

**Figure 7.4:** Verification of the RoleBinding configuration in YAML format showing the correct role and service account references.

### Authentication and Authorization

Authentication verifies the identity of the user or service account making a request, while authorization determines whether that identity is allowed to perform the requested action. In this lab, Kubernetes recognized `system:serviceaccount:dev:dev-user` as a valid service account. RBAC then allowed the service account to list pods in the `dev` namespace but denied permission to delete pods or access resources in the `prod` namespace.

---

## Short-Answer Questions

### Q1: Why is attaching policies to groups better than attaching them directly to users?

Attaching policies to groups rather than directly to users is a best practice for several reasons:

1. **Scalability**: When you have hundreds of users, managing individual policy attachments becomes unmanageable. Groups allow you to manage permissions at scale.

2. **Consistency**: All members of a team or role get the same permissions automatically, eliminating inconsistencies.

3. **Auditability**: It's easier to audit who has what permissions by examining group memberships rather than tracking individual policy attachments.

4. **Maintenance**: Updating permissions requires changing only the group policy once, which immediately affects all members.

5. **Separation of Duties**: Groups align with job functions, making it clear who should have what access.

### Q2: What is the difference between an IAM User and an IAM Role?

| Aspect | IAM User | IAM Role |
|--------|----------|----------|
| **Permanence** | Permanent identity with long-term credentials | Temporary identity with short-term credentials |
| **Credentials** | Has static credentials (username/password, access keys) | Provides temporary security credentials that expire |
| **Purpose** | Represents a specific person or application | Used for delegation and cross-service access |
| **Authentication** | Directly authenticated using credentials | Assumed by authenticated users or services |
| **Use Case** | Long-term human or application identities | Cross-account access, service-to-service communication |

### Q3: Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

The Analyst account demonstrates least privilege by having only S3 read-only permissions. This means the Analyst can view data but cannot modify, delete, or create resources.

**Blast Radius Reduction:**
- If the Analyst account is compromised, the attacker can only **view** S3 data, not destroy or modify it
- The damage is limited to **information disclosure** rather than data corruption or service disruption
- The admin account, by contrast, would allow an attacker to delete resources, modify configurations, or compromise entire infrastructure
- This separation of duties ensures that credential compromise in one role doesn't lead to catastrophic system-wide failure

**Security Principle:**
This demonstrates **defense in depth** - even if one security control fails (the password is stolen), other controls (permissions) limit the potential damage.

### Q4: In Kubernetes, what is the difference between a Role and a RoleBinding?

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

- ☑ **Root user is not used for daily tasks** – A dedicated administrator account (`CloudAdmin_MELON`) was created to perform administrative tasks instead of using the root account.

- ☑ **Permissions are granted via groups/roles, not directly to individual users** – Administrative permissions were assigned through the `Admins` group in IAM, while Kubernetes permissions were managed using Roles and RoleBindings.

- ☑ **At least one least-privilege read-only identity was created and tested** – The `Analyst_MANGO` account was assigned the `AmazonS3ReadOnlyAccess` policy, providing only the minimum permissions required for its role.

- ☑ **Access keys were listed and rotation was demonstrated** – The access key for `Analyst_MANGO` was created, verified, and later deactivated to demonstrate secure credential management.

- ☑ **Kubernetes RBAC blocks unauthorised actions** – RBAC testing confirmed that the `dev-user` service account could list pods in the `dev` namespace but was denied permission to delete pods or access resources in the `prod` namespace.

---

## Cleanup & Teardown

To ensure no resources are left running after completing the lab, cleanup commands were executed. The Kubernetes cluster was deleted and the LocalStack container was stopped and removed.

```bash
# Remove the Kubernetes cluster
kind delete cluster --name ccse-lab1

# Stop and remove LocalStack
docker stop localstack && docker rm localstack
```

**Output:**

<img width="684" height="351" alt="cleanup" src="https://github.com/user-attachments/assets/a4d24ed6-8f67-457c-a56c-8eb61131fc1f" />

**Figure 8.0:** Successful cleanup and teardown of the lab environments.

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

## Conclusion

This lab demonstrated that secure access is achieved by giving users only the permissions they need. In LocalStack IAM, the administrator received permissions through the `Admins` group, while `Analyst_MANGO` was only allowed to read Amazon S3 resources. Creating and deactivating an access key also showed the importance of managing user credentials securely.

In Kubernetes, RBAC applied the same security concept. The `dev-user` service account could only read pods in the `dev` namespace and was not allowed to delete pods or access the `prod` namespace. Overall, this lab demonstrated how IAM groups, least-privilege access, and Kubernetes RBAC help protect cloud resources by limiting unnecessary permissions.

---

*End of Lab Report - IKB42603 Lab 1: Cloud Account Security, Identity & Access Management*
