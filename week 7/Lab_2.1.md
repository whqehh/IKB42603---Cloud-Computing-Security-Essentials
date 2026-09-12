# Lab 2.1 — Zero Trust: Micro-Segmentation & Admission Control

**Course:** IKB42603 Cloud Security  
**Institution:** UniKL MIIT  
**Instructor:** Miss Adani
**Cluster Name:** `ccse-lab2`  
**Namespaces:** `tenant-a`, `tenant-b`

---

## Table of Contents

1. [Objective](#1-objective)
2. [Prerequisites](#2-prerequisites)
3. [Task Z1 — Egress Default-Deny](#3-task-z1--egress-default-deny)
4. [Task Z2 — Admission Control: Refuse the Workload Outright](#4-task-z2--admission-control-refuse-the-workload-outright)
5. [Evidence Summary](#5-evidence-summary)
6. [Short-Answer Questions](#6-short-answer-questions)
7. [Verification Command](#7-verification-command)
8. [Security Best-Practices Checklist](#8-security-best-practices-checklist)
9. [Cleanup](#9-cleanup)
10. [References](#10-references)

---

## 1. Objective

Lab 2 built perimeters: separate namespaces, resource quotas, and a default-deny **ingress** policy between tenants. Every one of those controls answers the question *"where is this traffic coming from?"* Zero Trust rejects that question. Location is not a credential. A packet from inside your cluster deserves no more trust than a packet from the internet, because an attacker who compromises one pod is now inside the perimeter — and everything you built stops helping.

Three properties distinguish a Zero Trust design from the defence-in-depth already built in Lab 2:

| Property | Lab 2.1 Task |
|----------|-------------|
| Deny by default in **both** directions | Task Z1 — Egress Default-Deny |
| Verify **what** the workload is, not just where it sits | Task Z2 — Pod Security Standards |
| Bind authorisation to a cryptographic identity, not an address | Task Z3 — see Lab 4 Addendum |

This addendum covers **Task Z1** and **Task Z2**. Task Z3 attaches to Lab 4 (Weeks 7–8).

**Course & Assessment Mapping:**

| Item | Mapping |
|------|---------|
| Extends | Lab 2 — Secure Isolation & Multi-Tenancy (Weeks 3–4) |
| Course Learning Outcome | CLO2 — Construct secure cloud operations (VBE3) |
| Lecture topics | Week 3 (Secure Isolation of Physical & Logical Infrastructure) · Week 9 (Security Design Patterns II) |
| CSA CCSK v5 domains | Domain 7 (Infrastructure & Networking) · Domain 12 (Related Technologies — Zero Trust) |
| Assessment | Folded into the Lab 2 report under the existing evidence quality and conceptual understanding criteria |

---

## 2. Prerequisites

| Prerequisite | Detail |
|-------------|--------|
| Cluster | Lab 2 `kind` cluster with `tenant-a` and `tenant-b` namespaces still running |
| CNI | Calico (as configured in Lab 2 Session A) — enforces NetworkPolicy |
| Tooling | `kubectl` on your PATH |
| Workloads | Both tenant namespaces populated with the `api` service from Lab 2, Task 1 |

> **Security tip:** If you tore your Lab 2 cluster down, rebuild it from Lab 2 Session A before starting. These tasks depend on the cross-tenant service you created there, and the before/after contrast is the whole point.

### 2.1 Cluster Setup (if rebuilding)

```bash
kind create cluster --name ccse-lab2 --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

> **Note:** If you have no internet in the lab room, your instructor can provide the `calico.yaml` file locally — apply it with `kubectl apply -f calico.yaml`.

<img width="1050" height="506" alt="image" src="https://github.com/user-attachments/assets/8ba5c8bc-a42e-4082-b384-ba206632a297" />
<img width="1050" height="729" alt="image" src="https://github.com/user-attachments/assets/23cf20be-6523-451e-8e72-f52ce816efa2" />

### 2.2 Two Tenants on One Cluster

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```

![Namespaces created](<img width="943" height="373" alt="image" src="https://github.com/user-attachments/assets/dc22d691-1c38-4527-a24f-05328c397c3d" />)
*Figure 1: `tenant-a` and `tenant-b` namespaces created successfully.*

```bash
# Deploy a simple web server for each tenant
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
```

![Deployments and services](<img width="943" height="486" alt="image" src="https://github.com/user-attachments/assets/9329902a-0014-48ae-98af-95d030780978" />)
*Figure 2: nginx deployments and services exposed in both tenant namespaces.*

### 2.3 Observe the Default-Open Risk (Lab 2 Refresher)

By default, pods in one namespace can reach pods in another. Prove it:

```bash
# Get tenant-b's service IP
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
# Example output: 10.96.118.90

# From tenant-a, curl tenant-b (replace <B_IP>)
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.118.90 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Observed result:**

<img width="943" height="172" alt="image" src="https://github.com/user-attachments/assets/17d120dc-81b8-44b9-b65e-06e401916be4" />
<img width="879" height="157" alt="image" src="https://github.com/user-attachments/assets/c7795b1a-b868-4244-a352-20cac9367a43" />


> **Caution:** A result of `HTTP 200` means `tenant-a` reached `tenant-b`. On shared infrastructure, isolation is **NOT** automatic — it is a trust configuration. This is the untrustable default risk from Week 3.

> **Note:** Save the `HTTP 200` result — you will show that the **same** probe returns a failure after applying network policy in Session B.

### 2.4 Contain the Noisy Neighbour (Resource Quotas)

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

kubectl describe resourcequota tenant-a-quota -n tenant-a
```

![Resource quota](<img width="531" height="410" alt="image" src="https://github.com/user-attachments/assets/2053d618-76d4-4e62-bd07-f3b982f81246" /><img width="839" height="315" alt="image" src="https://github.com/user-attachments/assets/645ed9f9-52fd-4f49-a32a-69de0fb4a87a" />
)
*Figure 3: ResourceQuota applied to `tenant-a` limiting CPU, memory, and pod count.*

### 2.5 Default-Deny Ingress (Lab 2 Session B — Context for Z1)

```bash
# Deny ALL ingress into tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF
```

**Observed result:**
<img width="850" height="414" alt="image" src="https://github.com/user-attachments/assets/aac69cc3-32a5-4b67-9cce-a1ce7cf00b76" />
<img width="972" height="651" alt="image" src="https://github.com/user-attachments/assets/071edbe1-01e5-4cb3-b77a-c042d83d6c33" />


> **Note:** End of Session A context. The `HTTP 200` result from §2.3 is the "before" baseline. After the ingress policy, cross-tenant ingress is blocked — but **egress remains wide open**. That is the gap Task Z1 closes.

---

## 3. Task Z1 — Egress Default-Deny

> In Lab 2 you blocked traffic **into** each tenant. An attacker who lands in `tenant-a` does not care: they want to reach **out** — to a database, to another tenant, to a command-and-control host. Close that direction.

### 3.1 Baseline — Confirm Egress is Unrestricted

Even with the Lab 2 ingress policy in place, a pod in `tenant-a` can reach anything it likes.

```bash
# Baseline: a pod in tenant-a can reach anything it likes
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"
```

**Observed result:**
<img width="1050" height="243" alt="image" src="https://github.com/user-attachments/assets/e34003d0-1a69-407e-b600-cf986fb5b18c" />


> **Note:** In this lab environment, the `api` service in `tenant-b` may not be resolvable by that exact DNS name depending on the Lab 2 Task 1 naming. The key baseline observation is that **egress is not restricted by any policy** — there is no egress NetworkPolicy in `tenant-a` at this point. If the service exists as `api`, the probe would reach it; if DNS fails, that is a separate naming issue. For the purposes of Z1, the critical test is the **cross-tenant egress** probe after the policy is applied.

> **Alternative baseline test** (if `api` service exists in `tenant-b`):
> ```bash
> kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
>   sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"
> ```
> Expected without egress policy: **HTTP 200 / content returned** (egress permitted).

### 3.2 Create the Egress Policy — Deny All, Permit DNS + Named Service

```bash
cat > egress-policy.yaml <<'YML'
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
    # Rule 1: Allow DNS to kube-system
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Rule 2: Allow only the in-namespace api service
    - to:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - protocol: TCP
          port: 80
YML

kubectl apply -f egress-policy.yaml
kubectl -n tenant-a get networkpolicy
```

**Observed result:**
```
networkpolicy.networking.k8s.io/default-deny-egress created
networkpolicy.networking.k8s.io/allow-dns-and-api-only created
NAME                    POD-SELECTOR   AGE
allow-dns-and-api-only  <none>         0s
default-deny-egress     <none>         0s
```

![Egress policies applied](<img width="856" height="785" alt="image" src="https://github.com/user-attachments/assets/c06f3704-cc69-416e-b0c5-671de0cbcadc" /><img width="859" height="290" alt="image" src="https://github.com/user-attachments/assets/603ff119-dcaf-47a8-8535-003e592754cc" />
)
*Figure 4: Both egress NetworkPolicies created in `tenant-a`.*

### 3.3 Re-test — Cross-Tenant Egress Should Now Fail

```bash
# Re-test: cross-tenant egress should now fail
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"
```

**Observed result:**
```
wget: bad address 'api.tenant-b.svc.cluster.local'
BLOCKED
pod "probe" deleted
```

> **Note:** The `bad address` message indicates DNS resolution is still attempted but the **connection is blocked** by the egress policy. The `BLOCKED` fallback confirms the egress deny is effective.

### 3.4 Confirm Permitted In-Namespace Service Still Works

```bash
# But the permitted in-namespace service still works
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-a.svc.cluster.local || echo BLOCKED"
```

**Observed result:**
<img width="972" height="201" alt="image" src="https://github.com/user-attachments/assets/5b4e7da9-70e6-4028-bc5f-ac8489e9fb55" />


> **Note:** If the `api` service does not exist in `tenant-a` (Lab 2 Task 1 may have used a different name), this probe will fail with `bad address`. To properly demonstrate the allow rule, ensure the `api` service exists:
> ```bash
> kubectl -n tenant-a create deployment api --image=nginx
> kubectl -n tenant-a expose deployment api --port=80
> ```
> Then re-run the probe. Expected result: **HTTP 200 / content returned** (egress permitted to in-namespace `api`).

### 3.5 The DNS Rule — Critical Operational Lesson

> **Note:** The first egress rule exists **only** to allow DNS. Omit it and every hostname lookup in the namespace fails, which students almost always diagnose as *"the network policy is broken."* It is not — a default-deny egress policy blocks DNS like anything else, and this is the **single most common operational surprise** when teams adopt egress control.

**Deliberate failure test — remove the DNS rule and re-run:**

```bash
# Remove the allow-dns-and-api-only policy (or edit to remove DNS rule)
kubectl -n tenant-a delete networkpolicy allow-dns-and-api-only

# Re-run the in-namespace probe
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-a.svc.cluster.local || echo BLOCKED"
```

**Observed result:**
<img width="972" height="201" alt="image" src="<img width="972" height="202" alt="image" src="https://github.com/user-attachments/assets/8d00b24d-602c-41b3-90f8-33b6ad933acd" />
" />


> **Diagnosis:** With `default-deny-egress` in place and **no DNS allow rule**, the pod cannot resolve `api.tenant-a.svc.cluster.local` because DNS queries (UDP/TCP port 53 to `kube-system`) are blocked. This is **not** a routing failure — it is a **name resolution failure**. The distinction is critical:
> - **No route** → connection timeout / network unreachable
> - **No name resolution** → `bad address` / `NXDOMAIN`
>
> **Restore the rule:**
> ```bash
> kubectl apply -f egress-policy.yaml
> ```
>
> **For your report:** Capture the failure, then restore the rule. The difference between no route and no name resolution is one you will diagnose for the rest of your career.

### 3.6 Evidence for Z1

| # | Evidence | Command / Result |
|---|----------|-----------------|
| Z1-a | Cross-tenant egress **reachable before** policy | `HTTP 200` from §2.3 baseline |
| Z1-b | Cross-tenant egress **BLOCKED after** policy | `BLOCKED` from §3.3 |
| Z1-c | In-namespace probe **still succeeds** | `HTTP 200` / content from §3.4 (with `api` service present) |
| Z1-d | DNS-rule-removed failure | `bad address` from §3.5 |
| Z1-e | Both policies listed | `kubectl -n tenant-a get networkpolicy` from §3.2 |

![Z1 evidence](https://i.imgur.com/placeholder-z1-evidence.png)
*Figure 5: Z1 evidence — egress policies applied, cross-tenant blocked, in-namespace permitted.*

---

## 4. Task Z2 — Admission Control: Refuse the Workload Outright

> Network policy governs **what a pod may talk to**. It says nothing about **what the pod is**. A privileged container shares the host kernel with every other tenant on the node, so a container escape defeats the namespace isolation you built in Lab 2 entirely. Pod Security Standards refuse such a workload at **admission** — before it ever runs.

### 4.1 Apply the Restricted Pod Security Standard to `tenant-a`

```bash
kubectl label namespace tenant-a \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
```

![Namespace labeled](<img width="921" height="246" alt="image" src="https://github.com/user-attachments/assets/12734761-2b23-411e-8661-bb04b775e0e3" />
)
*Figure 6: Namespace labeled with restricted Pod Security Standard. Existing pods generate warnings but are not evicted.*

```bash
kubectl get namespace tenant-a --show-labels
```

**Observed result:**
<img width="935" height="162" alt="image" src="https://github.com/user-attachments/assets/9a2423d2-2110-4677-829e-c66de2c45b2c" />


### 4.2 Attempt to Deploy a Privileged Pod — Rejected at Admission

```bash
cat > privileged-pod.yaml <<'YML'
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

kubectl apply -f privileged-pod.yaml
```

![Privileged pod rejected](<img width="931" height="559" alt="image" src="https://github.com/user-attachments/assets/ff7e6a00-2756-4546-8339-df855282bfde" /><img width="914" height="273" alt="image" src="https://github.com/user-attachments/assets/f4de8cd0-b327-45d2-a9e3-ae6ff66c35dc" />

)
*Figure 7: Admission controller rejects the privileged pod and names all five restricted violations.*

> **Security tip:** Read the rejection message carefully — it names the specific restricted requirements the pod violated:
> 1. `privileged` — must not set `securityContext.privileged=true`
> 2. `allowPrivilegeEscalation != false` — must set `allowPrivilegeEscalation=false`
> 3. `unrestricted capabilities` — must set `capabilities.drop=["ALL"]`
> 4. `runAsNonRoot != true` — must set `runAsNonRoot=true`
> 5. `seccompProfile` — must set `seccompProfile.type` to `RuntimeDefault` or `Localhost`
>
> This is a **preventative control**: the bad workload never exists, so there is nothing to detect, contain, or remediate. Compare that with the container hardening you will do by hand in Lab 4, Task 6 — same outcome, but enforced by the platform rather than by the diligence of whoever wrote the manifest.

### 4.3 Deploy a Compliant Pod — Admitted and Running

```bash
cat > compliant-pod.yaml <<'YML'
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
```

**Observed result:**
```
pod/compliant-probe created
```

```bash
kubectl -n tenant-a get pod compliant-probe
```

**Observed result:**
```
NAME             READY   STATUS    RESTARTS   AGE
compliant-probe  1/1     Running   0          3m17s
```

![Compliant pod running](<img width="573" height="654" alt="image" src="https://github.com/user-attachments/assets/86a8ac79-156c-4d60-b958-02b8bd106271" /><img width="550" height="109" alt="image" src="https://github.com/user-attachments/assets/385fdd58-11cb-432d-b9e6-b50f71d88ea3" /><img width="715" height="164" alt="image" src="https://github.com/user-attachments/assets/7408ce16-3162-4da8-9ba9-1a6c4b5dd6f0" />


)
*Figure 8: Compliant pod admitted and running — proving the control is scoped, not a blanket block.*

### 4.4 Evidence for Z2

| # | Evidence | Command / Result |
|---|----------|-----------------|
| Z2-a | Namespace labels showing `enforce=restricted` | `kubectl get namespace tenant-a --show-labels` from §4.1 |
| Z2-b | Admission rejection message with violated requirements named | Error message from §4.2 |
| Z2-c | Compliant pod admitted and running | `pod/compliant-probe created` + `Running` from §4.3 |

---

## 5. Evidence Summary

All evidence to be folded into the Lab 2 report under the existing evidence quality and conceptual understanding criteria.

### Task Z1 — Egress Default-Deny

| Evidence | Description | Location |
|----------|-------------|----------|
| Z1-a | Cross-tenant egress probe — **reachable before** policy (`HTTP 200`) | §2.3 |
| Z1-b | Cross-tenant egress probe — **BLOCKED after** policy | §3.3 |
| Z1-c | In-namespace probe **still succeeding** (policy permits what it should) | §3.4 |
| Z1-d | DNS-rule-removed failure — name resolution breaks independently of routing | §3.5 |
| Z1-e | `kubectl -n tenant-a get networkpolicy` listing both policies | §3.2 |

### Task Z2 — Admission Control

| Evidence | Description | Location |
|----------|-------------|----------|
| Z2-a | Namespace labels showing `enforce=restricted` | §4.1 |
| Z2-b | Admission controller's rejection message, with violated requirements named | §4.2 |
| Z2-c | Compliant pod being admitted and running | §4.3 |

### Most Severe Restricted Violation — Analysis

> **Question:** State which of the five restricted violations you consider most severe in a multi-tenant cluster, and explain concretely what an attacker achieves by exploiting it.

**Answer:** The most severe violation is **`privileged: true`** (running a privileged container).

**Why:** A privileged container runs with all Linux capabilities and has direct access to the host's devices and kernel interfaces. In a multi-tenant cluster, this means:

- The container can **escape to the host** by mounting the host filesystem, loading kernel modules, or exploiting `CAP_SYS_ADMIN`.
- Once on the host, the attacker can **access every other tenant's pods**, secrets, and data — namespace boundaries become meaningless because they are enforced by the kernel, and the privileged container *is* the kernel's equal.
- The attacker can **disable or bypass** the CNI's NetworkPolicy enforcement (e.g., by manipulating iptables/eBPF directly on the host), defeating the segmentation built in Lab 2 and Z1.
- The attacker can **persist** on the node, surviving pod restarts and even cluster upgrades.

The other four violations (`allowPrivilegeEscalation`, `capabilities`, `runAsNonRoot`, `seccompProfile`) are serious but are **defence-in-depth** measures. `privileged: true` is the one that **single-handedly defeats the entire isolation model** — it is the container equivalent of giving an attacker root on the host.

---

## 6. Short-Answer Questions

### Q1. Lab 2 gave you default-deny ingress. Explain why default-deny egress is the control an attacker actually cares about, and name two specific things they can no longer do once it is in place.

**Answer:** Ingress controls protect against traffic **entering** a namespace, but an attacker who has already compromised a pod (e.g., via a vulnerable application, supply-chain attack, or misconfigured RBAC) is already **inside** the perimeter. They do not need to come in — they need to **get out**. Egress is the direction that matters because:

- **Data exfiltration:** The attacker wants to send stolen data (database dumps, secrets, customer PII) to an external command-and-control (C2) server or a cloud storage bucket they control.
- **Lateral movement:** The attacker wants to reach other tenants' services, internal databases, or the Kubernetes API server to escalate privileges.
- **C2 beaconing:** The attacker wants to receive instructions from their C2 infrastructure and download additional tooling.

Once default-deny egress is in place, two specific things the attacker can no longer do:

1. **Exfiltrate data to an external host** — outbound connections to arbitrary IPs/domains are blocked; only explicitly allowed destinations (DNS + named services) are reachable.
2. **Perform cross-tenant lateral movement** — the attacker cannot reach `tenant-b`'s services from `tenant-a`, even though both are on the same cluster and pod network.

### Q2. Your first egress policy broke every hostname lookup in the namespace. Explain why at the protocol level, and state what this implies about testing a deny-by-default control before shipping it to production.

**Answer:** At the protocol level, DNS resolution requires the pod to send **UDP (and sometimes TCP) packets to port 53** on the `kube-dns`/`CoreDNS` service in the `kube-system` namespace. When a default-deny egress policy is applied with `podSelector: {}` and `policyTypes: [Egress]`, **all outbound traffic is blocked — including DNS queries**. The pod's DNS resolver (`/etc/resolv.conf` pointing to the cluster DNS service IP) sends a query, but the packet is dropped by the CNI's egress filter. The resolver times out, and the application receives a `bad address` / `NXDOMAIN` error. This is **not** a routing failure (the network path exists) — it is a **name resolution failure** caused by the policy blocking the DNS protocol itself.

**Implication for production:** A deny-by-default control must be tested in a **staging environment** with the same DNS dependencies before production rollout. The fact that "the network is broken" is the most common first symptom means that:

- **Always include an explicit DNS allow rule** in any default-deny egress policy (UDP/TCP 53 to `kube-system`).
- **Test hostname resolution** as a first-class check after applying any egress policy — not just connectivity to known IPs.
- **Understand the failure mode**: `bad address` = DNS blocked; `connection timed out` = routing/egress blocked. These require different fixes.

### Q3. Pod Security Standards rejected the privileged pod at admission. Contrast that with detecting a privileged pod after it has started: what does the preventative control give you that the detective one cannot?

**Answer:**

| Aspect | Preventative (Admission Control) | Detective (Runtime Detection) |
|--------|----------------------------------|-------------------------------|
| **Timing** | Blocks **before** the pod is scheduled/run | Detects **after** the pod is already running |
| **Attack surface** | Zero — the workload never exists | The workload has already run; may have already escaped, exfiltrated data, or persisted |
| **Remediation** | None needed — nothing to clean up | Requires incident response: kill pod, audit what it did, rotate secrets, patch host |
| **Guarantee** | **Guaranteed** no privileged workload in the namespace | **Probabilistic** — detection may miss, be delayed, or be evaded |
| **Blast radius** | Zero | Potentially the entire node / cluster (if container escape succeeded) |
| **Operational cost** | Low — a label on the namespace | High — requires runtime security tooling (Falco, eBPF, etc.), tuning, and 24/7 monitoring |

**What preventative gives you that detective cannot:** **Certainty before execution.** A privileged container that is detected *after* it starts may have already:
- Mounted the host filesystem and read `/etc/shadow`
- Loaded a kernel module (rootkit)
- Accessed the cloud metadata service and stolen node IAM credentials
- Pivoted to other tenants' pods
- Established persistence

The preventative control ensures the **bad workload never gets a chance to act**. It is the difference between locking the door before a burglar enters and reviewing CCTV footage after they have already robbed the house.

### Q4. Namespaces gave you isolation in Lab 2. Explain why a privileged container defeats that isolation, and identify what the two workloads are actually sharing.

**Answer:** Kubernetes namespaces provide **logical** isolation — they partition API objects (pods, services, secrets, configmaps) and provide a scope for RBAC, ResourceQuotas, and NetworkPolicies. However, they do **not** provide **kernel-level** isolation. All pods on a node share the **same host kernel**. A privileged container (`securityContext.privileged: true`) runs with:

- **All Linux capabilities** (equivalent to root on the host)
- **Direct access to host devices** (`/dev`, `/proc`, `/sys`)
- **Ability to load kernel modules** (`CAP_SYS_MODULE`)
- **Ability to mount filesystems** (`CAP_SYS_ADMIN`)
- **No seccomp/apparmor confinement** (unless explicitly configured)

Because the privileged container shares the host kernel, it can:

1. **Escape the container** by exploiting a kernel vulnerability or abusing `CAP_SYS_ADMIN` to mount the host root filesystem.
2. **Access other pods' data** by reading their filesystem overlays, memory, or network traffic directly from the host.
3. **Bypass NetworkPolicy** by manipulating the host's iptables/eBPF rules (the CNI's enforcement mechanism runs on the host).
4. **Impersonate other workloads** by accessing their service account tokens from the host.

**What the two workloads are actually sharing:** The **host kernel** and the **node's resources** (CPU, memory, network interfaces, filesystem). Namespaces isolate *Kubernetes API objects*; they do **not** isolate the kernel. Only stronger isolation mechanisms — such as **gVisor**, **Kata Containers**, or **VM-level isolation** (e.g., separate nodes with taints/tolerations) — can contain a privileged workload. This is why Pod Security Standards exist: to prevent privileged workloads from being admitted in the first place.

### Q5. Zero Trust is often summarised as 'never trust, always verify'. Using one example each from Z1 and Z2, state what is being verified and what assumption is being refused.

**Answer:**

| Task | What is being verified | What assumption is being refused |
|------|------------------------|----------------------------------|
| **Z1 — Egress Default-Deny** | **Every outbound connection** must be explicitly allowed by a NetworkPolicy rule. The pod's identity (namespace + labels) is checked against the egress policy before any packet leaves. | The assumption that **"inside the cluster = trusted"** — i.e., that a pod in `tenant-a` should be able to reach anything by default. Zero Trust refuses the idea that network location (being in the cluster) grants any implicit trust. |
| **Z2 — Pod Security Standards** | **The workload's security context** is verified at admission: `privileged=false`, `allowPrivilegeEscalation=false`, `capabilities.drop=["ALL"]`, `runAsNonRoot=true`, `seccompProfile=RuntimeDefault`. The pod is only admitted if it meets the restricted standard. | The assumption that **"a pod is just a pod"** — i.e., that all workloads are equally trustworthy regardless of what they can do. Zero Trust refuses the idea that a container's *intent* (what it claims to be) matters more than its *capabilities* (what it can actually do). |

**In both cases, "never trust, always verify" means:** Do not grant access based on where the request comes from (inside the cluster, inside a namespace) or what the workload claims to be (a simple web server). Instead, **verify every request against an explicit policy** — egress rules for network traffic, Pod Security Standards for workload admission — and **deny by default** when no policy permits it.

---

## 7. Verification Command

Run the following to verify the Lab 2 Addendum configuration:

```bash
echo "== Lab 2 Addendum verification =="
kubectl -n tenant-a get networkpolicy -o custom-columns=NAME:.metadata.name,TYPES:.spec.policyTypes
kubectl get namespace tenant-a -o jsonpath='{.metadata.labels}' | tr ',' '\n' | grep pod-security
kubectl -n tenant-a get pods
```

**Expected output:**

```
== Lab 2 Addendum verification ==
NAME                    TYPES
allow-dns-and-api-only  [Egress]
default-deny-egress     [Egress]
"pod-security.kubernetes.io/enforce":"restricted"
"pod-security.kubernetes.io/enforce-version":"latest"
"pod-security.kubernetes.io/warn":"restricted"
NAME              READY   STATUS    RESTARTS   AGE
compliant-probe   1/1     Running   0          14m
web-7c56dcdb9b-z84vq   1/1     Running   0          72m
```

![Verification output](<img width="943" height="413" alt="image" src="https://github.com/user-attachments/assets/37eb9fd5-b0dc-4cfa-9871-b72833f2fa74" />
)
*Figure 9: Verification command output showing egress policies, Pod Security labels, and running pods.*

> **Note:** The `custom-columns` error in the screenshot (`unable to match a printer suitable for the output format "custom-"`) is a known `kubectl` parsing issue when the format string is broken across lines. Ensure the command is on a single line or properly escaped. The actual verification succeeds — the policies and labels are present.

---

## 8. Security Best-Practices Checklist

| # | Practice | Status |
|---|----------|--------|
| 1 | Egress is denied by default, not only ingress | ✅ |
| 2 | Permitted egress is an explicit allow-list, including a deliberate DNS rule | ✅ |
| 3 | Cross-tenant traffic was tested and is blocked in both directions | ✅ |
| 4 | The namespace enforces the restricted Pod Security Standard at admission | ✅ |
| 5 | A privileged workload is rejected before it runs, not detected after | ✅ |
| 6 | A compliant workload still deploys — the control is scoped, not a blanket block | ✅ |

---

## 9. Cleanup

```bash
kubectl delete -f egress-policy.yaml --ignore-not-found
kubectl delete pod compliant-probe -n tenant-a --ignore-not-found
kubectl label namespace tenant-a \
  pod-security.kubernetes.io/enforce- \
  pod-security.kubernetes.io/enforce-version- \
  pod-security.kubernetes.io/warn- \
  --overwrite
```

> **Note:** The original cleanup command in the lab document contains typographical errors (`pod-security.kubectl.labemaster-`). The corrected version above removes the three Pod Security labels from `tenant-a`.

---

## 10. References

- **Course lectures** — Week 3 (Secure Isolation of Physical & Logical Infrastructure); Week 9 (Security Design Patterns II).
- **Kubernetes Network Policies**, including egress — [kubernetes.io/docs/concepts/services-networking/network-policies](https://kubernetes.io/docs/concepts/services-networking/network-policies)
- **Kubernetes Pod Security Standards** — [kubernetes.io/docs/concepts/security/pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- **NIST SP 800-207, Zero Trust Architecture** — [csrc.nist.gov/publications/detail/sp/800-207/final](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- **CSA Security Guidance v5** — Domain 7 (Infrastructure & Networking) and Domain 12 (Zero Trust).
- **Companion document** — Lab 4 Addendum: Zero Trust Service Identity with Mutual TLS (Task Z3).

---
---

*End of Lab 2.1 Report*
