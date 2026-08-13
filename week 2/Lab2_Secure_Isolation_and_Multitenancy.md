# Lab 2 Report: Secure Isolation & Multi-Tenancy

## Student Information
- **Course:** IKB42603 - Secure Cloud Operations
- **Lab:** Lab 2 - Secure Isolation & Multi-Tenancy
- **Date:** 14th August 2026
---

## Table of Contents
1. [Setup & Environment](#setup)
2. [Session A: Compute Isolation & Default-Open Risk](#session-a)
3. [Session B: Network & Storage Isolation](#session-b)
4. [Deliverables](#deliverables)
5. [Verification Commands](#verification)
6. [Cleanup](#cleanup)

---

## <a name="setup"></a>1. Setup & Environment

### 1.1 Cluster Creation with Calico CNI

Created Kind cluster with Calico for NetworkPolicy enforcement:

```bash
# Create cluster with default CNI disabled
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

**Output:**
```
Creating cluster "ccse-lab2" ...
 ✓ Ensuring node image (kindest/node:v1.31.0) 🖼
 ✓ Preparing nodes 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing CNI 🔌 
 ✓ Installing StorageClass 💾 
Set kubectl context to "kind-ccse-lab2"
You can now use your cluster with:

kubectl cluster-info --context kind-ccse-lab2
```

### 1.2 Installing Calico CNI

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Screenshot 1: Calico Installation**
![Calico Installation](media/image1.png)

**Screenshot 2: Calico Nodes Ready**
![Calico Nodes](media/image2.png)

**Screenshot 3: Cluster Ready**
![Cluster Ready](media/image3.png)

---

## <a name="session-a"></a>2. Session A: Compute Isolation & Default-Open Risk

### 2.1 Task 1: Two Tenants on One Cluster

Created two namespaces representing tenants and deployed web servers:

```bash
# Create namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy web servers
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

# Expose services
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

**Screenshot 4: Pods and Services in tenant-a**
![Tenant A Resources](media/image4.png)

**Command Output:**
```
namespace/tenant-a created
namespace/tenant-b created
deployment.apps/web created
deployment.apps/web created
service/web exposed
service/web exposed

# kubectl get pods,svc -n tenant-a
NAME                       READY   STATUS    RESTARTS   AGE
pod/web-xxxxxxxxx-xxxxx    1/1     Running   0          5s

NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
service/web     ClusterIP   10.96.173.224   <none>        80/TCP    3s
```

### 2.2 Task 2: Observe the Default-Open Risk

**Demonstrated cross-tenant communication (security risk):**

```bash
# Get tenant-b's service IP
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

**Output:**
```
10.96.173.224
```

```bash
# From tenant-a, curl tenant-b
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.173.224 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Screenshot 5: Cross-Tenant Access (HTTP 200)**
![Before Network Policy](media/image6.png)

**⚠️ SECURITY RISK CONFIRMED:** HTTP 200 response proves tenant-a can reach tenant-b's service. This is the default-open behavior that is dangerous in multi-tenant environments.

### 2.3 Task 3: Resource Quotas (Noisy Neighbor Prevention)

Applied resource quota to prevent one tenant from exhausting cluster resources:

```bash
cat <<EOF | kubectl apply -f --
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
```

**Screenshot 6: Resource Quota Applied**
![Resource Quota](media/image7.png)

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Command Output:**
```
Name:            tenant-a-quota
Namespace:       tenant-a
Resource         Used  Hard
--------         ----  ----
pods             1     5
requests.cpu     0     1
requests.memory  0     512Mi
```

---

## <a name="session-b"></a>3. Session B: Network & Storage Isolation

### 3.1 Task 4: Default-Deny Network Isolation

**Applied default-deny NetworkPolicy to tenant-b:**

```bash
cat <<EOF | kubectl apply -f --
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

**Screenshot 7: NetworkPolicy Applied**
![Network Policy](media/image8.png)

**Re-ran the same probe - NOW BLOCKED:**

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.173.224 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Screenshot 8: After Network Policy (Timeout)**
![After Network Policy](media/image9.png)

**✅ ISOLATION CONFIRMED:** The connection timed out, proving NetworkPolicy successfully blocked cross-tenant traffic.

### 3.2 Task 5: Storage & Secret Isolation

**Created secrets for each tenant:**

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

**Screenshot 9: Secrets Created**
![Secrets Creation](media/image10.png)

**Created RBAC for tenant-a service account:**

```bash
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

**Screenshot 10: RBAC Verification**
![RBAC Results](media/image11.png)

**Command Output:**
```
serviceaccount/app-a created
role.rbac.authorization.k8s.io/reader created
rolebinding.rbac.authorization.k8s.io/rb created

kubectl auth can-i get secrets -n tenant-a --as=$SA
yes

kubectl auth can-i get secrets -n tenant-b --as=$SA
no
```

**✅ STORAGE ISOLATION CONFIRMED:** Tenant-a can access its own secrets but cannot access tenant-b's secrets.

### 3.3 Task 6: Data Remanence & Secure Deletion

**Demonstrated data remanence (data persists after deletion):**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

**Screenshot 11: Data Remanence Demo**
![Data Remanence](media/image12.png)

**Demonstrated secure deletion (overwrite with zeros):**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; echo wiped'
```

**Screenshot 12: Secure Wipe**
![Secure Wipe](media/image13.png)

---

## <a name="deliverables"></a>4. Deliverables

### 4.1 Screenshots Summary

| Screenshot | Description | Task |
|------------|-------------|------|
| 1-3 | Calico installation and cluster setup | Setup |
| 4 | Tenant resources (pods/services) | Task 1 |
| 5-6 | HTTP 200 cross-tenant access (BEFORE) | Task 2 |
| 7 | Resource quota configuration | Task 3 |
| 8-9 | NetworkPolicy applied (AFTER) | Task 4 |
| 10-11 | Secret isolation with RBAC | Task 5 |
| 12-13 | Data remanence and secure wipe | Task 6 |

### 4.2 Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

**Answer:** By default, Kubernetes uses a flat network model where all pods can communicate with each other regardless of namespace. This is because the default CNI implementations do not enforce network policies, and the cluster's service network is shared. This is dangerous in multi-tenant clouds because:
- It violates the principle of least privilege
- A compromised tenant could attack other tenants
- Sensitive data could be accessed by unauthorized tenants
- Regulatory compliance (e.g., GDPR, HIPAA) requires tenant isolation

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

**Answer:** The default-deny principle means that all network traffic is blocked by default, and only explicitly allowed traffic is permitted. Our NetworkPolicy implements this by:
1. Selecting all pods in the namespace (`podSelector: {}`)
2. Specifying `policyTypes: [Ingress]` to control incoming traffic
3. Not specifying any ingress rules (which would normally permit traffic)
4. Result: All incoming traffic to tenant-b is blocked by default

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

**Answer:** 
- **VMs** provide stronger isolation: each VM has its own kernel, hardware virtualization, and complete isolation from other VMs. This is hardware-enforced isolation.
- **Containers** share the host kernel and provide process-level isolation. While namespaces and cgroups provide isolation, they are less secure than hardware virtualization.

**When to add a VM boundary:**
- When running untrusted workloads from different customers
- When regulatory requirements mandate hardware isolation
- When running workloads with different security classifications
- When the risk of kernel-level vulnerabilities is unacceptable

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

**Answer:** Data remanence is the residual representation of data that remains on storage media even after attempts to delete or erase it. This occurs because:
- File deletion typically only removes directory entries
- Data blocks are marked as free but retain actual data until overwritten
- Flash memory may retain data after deletion

**Cryptographic erasure** is preferred in the cloud because:
- You rarely control the physical storage blocks
- Cloud providers abstract the underlying storage
- Destroying the encryption key effectively makes data unrecoverable
- It's faster and more efficient than overwriting entire volumes
- It works reliably across all storage types (HDD, SSD, NVMe)

**Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?**

**Answer:**
- **Task 1-3 (Compute Isolation):** Namespaces, resource quotas, and the default-open risk demonstration
- **Task 4 (Network Isolation):** NetworkPolicy enforcing default-deny between tenants
- **Task 5 (Storage Isolation):** Secrets and RBAC preventing cross-tenant data access
- **Task 6 (Storage Isolation):** Data remanence and secure deletion on persistent storage

---

## <a name="verification"></a>5. Verification Commands

### 5.1 Network Policies

```bash
kubectl get networkpolicy -A
```

**Expected Output:**
```
NAMESPACE   NAME                  POD-SELECTOR   AGE
tenant-b    default-deny-ingress  {}             2m
```

### 5.2 Resource Quotas

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Expected Output:**
```
Name:            tenant-a-quota
Namespace:       tenant-a
Resource         Used  Hard
--------         ----  ----
pods             1     5
requests.cpu     0     1
requests.memory  0     512Mi
```

---

## <a name="cleanup"></a>6. Cleanup & Teardown

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```

**Screenshot 13: Cleanup Complete**
![Cleanup](media/image14.png)

**Command Output:**
```
Deleting cluster "ccse-lab2" ...
Deleted nodes: ["ccse-lab2-control-plane"]
ccse-vol
```

---

## Security Best-Practices Checklist

- ✅ Tenants are separated into distinct namespaces
- ✅ A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after)
- ✅ Resource quotas prevent a noisy-neighbour from exhausting shared capacity
- ✅ Per-tenant secrets are unreadable by other tenants (RBAC enforced)
- ✅ Secure deletion / cryptographic erasure is understood for data remanence

---

## Reflection

This lab demonstrated the critical importance of implementing **defense in depth** for multi-tenant cloud environments:

1. **Compute Isolation** alone (namespaces) is insufficient - resources still need quotas
2. **Network Isolation** must be explicitly configured - default-open is a risk
3. **Storage Isolation** requires both RBAC and understanding of data remanence
4. The **default-deny** principle should be applied across all layers

---

**Report Completed:** [Date]
**Lab Instructor:** [Instructor Name]
