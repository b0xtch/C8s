#!/usr/bin/env bash
# run-kubernetes.sh: run one pod CVM as a Kubernetes pod and run the hardware
# suite against its pod address.
#
# The pod is the shape samples/pod-cvm.yaml documents: one launcher container,
# no privilege beyond NET_ADMIN, device nodes from KubeVirt's device plugin,
# the guest on the pod's own interface. The script creates a namespace for it
# and deletes that namespace when it is done.
#
# Usage: test/podcvm/run-kubernetes.sh
#
#   C8S_POD_IMAGE_DIR       pod guest image directory ON THE NODE. Required.
#   C8S_POD_LAUNCHER_IMAGE  launcher container image, already present on the
#                           node or pullable. Required.
#   C8S_POD_NAMESPACE       namespace to create (default c8s-pod-hw)
#   C8S_POD_VSOCK_CID       guest vsock CID (default: none)
#   C8S_POD_QUOTE_DIR       node directory holding qgs.socket (default
#                           /run/tdx-qgs)
#   C8S_POD_COLLATERAL      collateral modes to run (default "required skip")
#   C8S_POD_ACCEPT_TCB      TCB statuses to accept besides UpToDate, comma
#                           separated, for a host whose TCB is behind
#   C8S_POD_VCPUS, C8S_POD_MEMORY_MIB, C8S_POD_SCRATCH   guest shape (2, 2048, 4G)
#   C8S_POD_BOOT_TIMEOUT    seconds to wait for the guest (default 240)
#   C8S_POD_KEEP=1          leave the namespace in place for inspection
#   C8S_POD_OUT             directory for logs and results (default: a new
#                           temporary directory, kept)
#   KUBECTL                 kubectl command (default kubectl)
#   C8S_BIN, C8S_POD_HW_TEST  prebuilt binaries (default: built here)
#
# Run it where pod addresses are routable, which on a single node is the node.
# The namespace is labelled for the privileged Pod Security level: the pod
# mounts two host paths and adds NET_ADMIN, which baseline forbids.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image_dir="${C8S_POD_IMAGE_DIR:?set C8S_POD_IMAGE_DIR to the pod guest image directory on the node}"
launcher_image="${C8S_POD_LAUNCHER_IMAGE:?set C8S_POD_LAUNCHER_IMAGE to the launcher container image}"
namespace="${C8S_POD_NAMESPACE:-c8s-pod-hw}"
modes="${C8S_POD_COLLATERAL:-required skip}"
boot_timeout="${C8S_POD_BOOT_TIMEOUT:-240}"
memory_mib="${C8S_POD_MEMORY_MIB:-2048}"
out="${C8S_POD_OUT:-$(mktemp -d -t c8s-pod-k8s.XXXXXX)}"
manifest="$image_dir/manifest.json"
read -r -a kubectl <<<"${KUBECTL:-kubectl}"

die() { echo "run-kubernetes: $*" >&2; exit 2; }
command -v curl >/dev/null || die "curl is required to probe the agent"
[[ -f "$manifest" ]] || die "$manifest is missing (the script reads the manifest from the same path the node mounts)"
mkdir -p "$out/bin" || die "cannot create $out"

c8s="${C8S_BIN:-}"
if [[ -z "$c8s" ]]; then
  c8s="$out/bin/c8s"
  (cd "$repo_root" && CGO_ENABLED=0 go build -trimpath -o "$c8s" ./cmd/c8s) || die "building c8s failed"
fi
hwtest="${C8S_POD_HW_TEST:-}"
if [[ -z "$hwtest" ]]; then
  hwtest="$out/bin/podcvm-hw.test"
  (cd "$repo_root" && CGO_ENABLED=0 go test -c -tags podcvm_hardware -o "$hwtest" ./test/podcvm) || die "building the hardware suite failed"
fi

results=()
failed=0
record() { # record <PASS|FAIL> <step> [detail]
  results+=("$1  $2${3:+  ($3)}")
  [[ "$1" == PASS ]] || failed=1
  echo "== $1: $2${3:+ ($3)}"
}

# shellcheck disable=SC2329 # runs from the EXIT trap
cleanup() {
  "${kubectl[@]}" -n "$namespace" logs sbx-hw --tail=200 >"$out/launcher.log" 2>&1
  "${kubectl[@]}" -n "$namespace" describe pod sbx-hw >"$out/pod-describe.txt" 2>&1
  if [[ "${C8S_POD_KEEP:-0}" != 1 ]]; then
    "${kubectl[@]}" delete namespace "$namespace" --wait=true --timeout=120s >/dev/null 2>&1
  fi
}

"${kubectl[@]}" get namespace "$namespace" >/dev/null 2>&1 && die "namespace $namespace already exists; delete it or set C8S_POD_NAMESPACE"

"$c8s" pod launch-config new --out "$out/bundle" --image-manifest "$manifest" \
  --tenant hw.tenant-a --sandbox hw-sandbox --credential test-token:128 >"$out/bundle.log" 2>&1 \
  || die "creating the launch bundle failed: $(tail -1 "$out/bundle.log")"

trap cleanup EXIT
"${kubectl[@]}" create namespace "$namespace" >/dev/null || die "cannot create namespace $namespace"
"${kubectl[@]}" label namespace "$namespace" --overwrite \
  pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/warn=privileged >/dev/null
"${kubectl[@]}" -n "$namespace" create configmap sbx-hw-launch --from-file="$out/bundle/opkeydata" >/dev/null \
  || die "cannot create the launch ConfigMap"

vsock_arg=""
[[ -n "${C8S_POD_VSOCK_CID:-}" ]] && vsock_arg="        - --vsock-cid=${C8S_POD_VSOCK_CID}"
cat >"$out/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sbx-hw
  namespace: ${namespace}
  labels:
    confidential.ai/pod-cvm: "true"
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 30
  automountServiceAccountToken: false
  enableServiceLinks: false
  containers:
    - name: launcher
      image: ${launcher_image}
      imagePullPolicy: IfNotPresent
      args:
        - --platform=tdx
        - --image-dir=/image
        - --launch-dir=/launch
        - --work-dir=/work
        - --name=sbx-hw
        - --vcpus=${C8S_POD_VCPUS:-2}
        - --memory=${memory_mib}M
        - --scratch=${C8S_POD_SCRATCH:-4G}
        - --quote-socket=/run/tdx-qgs/qgs.socket
${vsock_arg}
      securityContext:
        runAsUser: 0
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
          add: ["NET_ADMIN"]
      resources:
        requests:
          cpu: "1"
          memory: $((memory_mib + 512))Mi
        limits:
          memory: $((memory_mib + 512))Mi
          devices.kubevirt.io/kvm: "1"
          devices.kubevirt.io/tun: "1"
          devices.kubevirt.io/vhost-net: "1"
          devices.kubevirt.io/vhost-vsock: "1"
      volumeMounts:
        - {name: image, mountPath: /image, readOnly: true}
        - {name: launch, mountPath: /launch, readOnly: true}
        - {name: work, mountPath: /work}
        - {name: qgs, mountPath: /run/tdx-qgs}
  volumes:
    - name: image
      hostPath: {path: ${image_dir}, type: Directory}
    - name: launch
      configMap: {name: sbx-hw-launch}
    - name: work
      emptyDir: {}
    - name: qgs
      hostPath: {path: ${C8S_POD_QUOTE_DIR:-/run/tdx-qgs}, type: Directory}
EOF
started=$(date +%s.%N)
"${kubectl[@]}" apply -f "$out/pod.yaml" >/dev/null || die "the API server refused the pod: see $out/pod.yaml"

pod_ip=""
url=""
state=timeout
deadline=$(( $(date +%s) + boot_timeout ))
while (( $(date +%s) < deadline )); do
  phase=$("${kubectl[@]}" -n "$namespace" get pod sbx-hw -o jsonpath='{.status.phase}' 2>/dev/null)
  if [[ "$phase" == Failed || "$phase" == Succeeded ]]; then
    state=exited
    break
  fi
  pod_ip=$("${kubectl[@]}" -n "$namespace" get pod sbx-hw -o jsonpath='{.status.podIP}' 2>/dev/null)
  if [[ -n "$pod_ip" ]]; then
    url="https://$pod_ip:8443"
    if [[ "$(curl -sk --max-time 2 "$url/healthz" 2>/dev/null)" == ok ]]; then
      state=up
      break
    fi
  fi
  sleep 0.5
done
elapsed=$(awk -v a="$started" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')

if [[ "$state" != up ]]; then
  record FAIL "pod CVM serves its API on the pod address" "$state after ${elapsed}s, pod IP ${pod_ip:-none}"
else
  record PASS "pod CVM serves its API on the pod address" "${elapsed}s from apply to healthz at $url"
  if "$c8s" pod verify --url "$url" --bundle "$out/bundle" --image-manifest "$manifest" --collateral skip -o json >"$out/verify.json" 2>&1; then
    record PASS "c8s pod verify against the pod address"
  else
    record FAIL "c8s pod verify against the pod address" "$(cat "$out/verify.json")"
  fi
  for mode in $modes; do
    if C8S_POD_URL="$url" C8S_POD_BUNDLE="$out/bundle" C8S_POD_MANIFEST="$manifest" \
      C8S_POD_COLLATERAL="$mode" "$hwtest" -test.v -test.count=1 >"$out/suite-$mode.log" 2>&1; then
      record PASS "hardware suite through the pod network, collateral $mode"
    else
      record FAIL "hardware suite through the pod network, collateral $mode" "see $out/suite-$mode.log"
    fi
  done
fi

{
  echo "pod CVM Kubernetes run, $(date -u +%Y-%m-%dT%H:%M:%SZ), node $(hostname), kernel $(uname -r)"
  printf '%s\n' "${results[@]}"
} | tee "$out/summary.txt"
echo "run-kubernetes: logs in $out"
exit "$failed"
