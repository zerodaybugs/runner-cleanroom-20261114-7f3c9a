set -Eeuo pipefail
umask 077
NS="agc-policy-rotation-20261122"
if command -v cygpath >/dev/null 2>&1; then
  ARTIFACT_ROOT="$(cygpath -u "${BUILD_ARTIFACTSTAGINGDIRECTORY:?BUILD_ARTIFACTSTAGINGDIRECTORY missing}")"
else
  ARTIFACT_ROOT="${BUILD_ARTIFACTSTAGINGDIRECTORY:?BUILD_ARTIFACTSTAGINGDIRECTORY missing}"
fi
EVIDENCE="${ARTIFACT_ROOT}/agc-rotation-evidence"
mkdir -p "$EVIDENCE"
exec > >(tee -a "$EVIDENCE/run.log") 2>&1

echo "__RUN_START__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
az account show --query '{subscription:id,tenant:tenantId,user:user.name}' -o json | tee "$EVIDENCE/azure-account.json"

if ! command -v kubectl >/dev/null 2>&1; then
  az aks install-cli
fi
if az aks get-credentials -g msrc-fi-1114110503 -n fiaks1114110503 --overwrite-existing --admin; then
  echo "KUBECONFIG_MODE=admin"
else
  az aks get-credentials -g msrc-fi-1114110503 -n fiaks1114110503 --overwrite-existing
  if ! command -v kubelogin >/dev/null 2>&1; then
    az aks install-cli
  fi
  kubelogin convert-kubeconfig -l azurecli
  echo "KUBECONFIG_MODE=azurecli"
fi

kubectl version -o json | tee "$EVIDENCE/kubectl-version.json"
kubectl get nodes -o wide | tee "$EVIDENCE/nodes.txt"
kubectl get deployment -A -l app=alb-controller -o json | jq '{items:[.items[]|{namespace:.metadata.namespace,name:.metadata.name,image:.spec.template.spec.containers[0].image,uid:.metadata.uid}]}' | tee "$EVIDENCE/alb-controller.json"

BASE_GW_JSON="$(kubectl get gateway victim-gw -n agc-ls-victim -o json 2>/dev/null || true)"
if [ -z "$BASE_GW_JSON" ]; then
  BASE_GW_JSON="$(kubectl get gateway -A -o json | jq -c '[.items[]|select(.metadata.annotations["alb.networking.azure.io/alb-name"] != null)][0]')"
fi
ALB_NAME="$(jq -r '.metadata.annotations["alb.networking.azure.io/alb-name"] // empty' <<<"$BASE_GW_JSON")"
ALB_NAMESPACE="$(jq -r '.metadata.annotations["alb.networking.azure.io/alb-namespace"] // empty' <<<"$BASE_GW_JSON")"
if [ -z "$ALB_NAME" ] || [ -z "$ALB_NAMESPACE" ]; then
  echo "NO_READY_ALB_ANNOTATION" >&2
  exit 30
fi
echo "ALB_NAME=$ALB_NAME ALB_NAMESPACE=$ALB_NAMESPACE" | tee "$EVIDENCE/alb-binding.txt"

: "${KEY_A_PEM_B64:?KEY_A_PEM_B64 is required}"
: "${KEY_B_PEM_B64:?KEY_B_PEM_B64 is required}"
printf '%s' "$KEY_A_PEM_B64" | base64 -d > /tmp/key-a.pem
printf '%s' "$KEY_B_PEM_B64" | base64 -d > /tmp/key-b.pem
chmod 600 /tmp/key-a.pem /tmp/key-b.pem

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
make_token() {
  local key="$1" kid="$2" aud="$3" sub="$4"
  local now exp header payload unsigned sig
  now="$(date +%s)"
  exp="$((now+3600))"
  header="$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$kid" | b64url)"
  payload="$(printf '{"iss":"https://issuer.agc-rotation.invalid","aud":"%s","sub":"%s","iat":%s,"nbf":%s,"exp":%s}' "$aud" "$sub" "$now" "$((now-10))" "$exp" | b64url)"
  unsigned="${header}.${payload}"
  sig="$(printf '%s' "$unsigned" | openssl dgst -sha256 -sign "$key" -binary | b64url)"
  printf '%s.%s\n' "$unsigned" "$sig"
}
AUD1="api://agc-rotation"
AUD2="api://agc-rotation-new-audience"
TOKEN_A="$(make_token /tmp/key-a.pem agc-rotation-a-20261122 "$AUD1" subject-a)"
TOKEN_B="$(make_token /tmp/key-b.pem agc-rotation-b-20261122 "$AUD1" subject-b)"
TOKEN_A_AUD2="$(make_token /tmp/key-a.pem agc-rotation-a-20261122 "$AUD2" subject-a-aud2)"
printf '%s' "$TOKEN_A" | sha256sum | tee "$EVIDENCE/token-a.sha256"
printf '%s' "$TOKEN_B" | sha256sum | tee "$EVIDENCE/token-b.sha256"
printf '%s' "$TOKEN_A_AUD2" | sha256sum | tee "$EVIDENCE/token-a-aud2.sha256"

kubectl delete namespace "$NS" --ignore-not-found --wait=true || true
kubectl create namespace "$NS"

cat >/tmp/fixture.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rotation-content
  namespace: $NS
data:
  index.html: |
    <html><body><h1>MSRC_AGC_POLICY_ROTATION_PROTECTED_RECORD_4D81E7</h1></body></html>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rotation-backend
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rotation-backend
  template:
    metadata:
      labels:
        app: rotation-backend
    spec:
      containers:
      - name: web
        image: mcr.microsoft.com/azuredocs/aks-helloworld:v1
        ports:
        - containerPort: 80
        volumeMounts:
        - name: content
          mountPath: /app/templates/index.html
          subPath: index.html
          readOnly: true
      volumes:
      - name: content
        configMap:
          name: rotation-content
---
apiVersion: v1
kind: Service
metadata:
  name: rotation-backend
  namespace: $NS
spec:
  selector:
    app: rotation-backend
  ports:
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: rotation-gw
  namespace: $NS
  annotations:
    alb.networking.azure.io/alb-name: $ALB_NAME
    alb.networking.azure.io/alb-namespace: $ALB_NAMESPACE
spec:
  gatewayClassName: azure-alb-external
  listeners:
  - name: rotation-http
    hostname: agc-rotation.example.invalid
    port: 8081
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: rotation-route
  namespace: $NS
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: rotation-gw
    sectionName: rotation-http
  hostnames:
  - agc-rotation.example.invalid
  rules:
  - backendRefs:
    - group: ""
      kind: Service
      name: rotation-backend
      port: 80
EOF
kubectl apply -f /tmp/fixture.yaml
kubectl rollout status deployment/rotation-backend -n "$NS" --timeout=180s

wait_programmed() {
  local deadline=$((SECONDS+600))
  while (( SECONDS < deadline )); do
    local g r addr
    g="$(kubectl get gateway rotation-gw -n "$NS" -o json | jq -r '[.status.conditions[]?|select(.type=="Programmed")][0]|(.status+":"+.reason)' 2>/dev/null || true)"
    r="$(kubectl get httproute rotation-route -n "$NS" -o json | jq -r '[.status.parents[]?.conditions[]?|select(.type=="Programmed")][0]|(.status+":"+.reason)' 2>/dev/null || true)"
    addr="$(kubectl get gateway rotation-gw -n "$NS" -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)"
    echo "WAIT_PROGRAMMED gateway=$g route=$r address=$addr"
    if [ "$g" = "True:Programmed" ] && [ "$r" = "True:Programmed" ] && [ -n "$addr" ]; then
      return 0
    fi
    sleep 5
  done
  return 1
}
wait_programmed
FRONT="$(kubectl get gateway rotation-gw -n "$NS" -o jsonpath='{.status.addresses[0].value}')"
echo "FRONT=$FRONT" | tee "$EVIDENCE/front.txt"
kubectl get gateway,httproute,service,deployment -n "$NS" -o yaml >"$EVIDENCE/fixture-state.yaml"

request() {
  local label="$1" token="${2:-}" marker code
  marker="${label}-$(date +%s%N)"
  if [ -n "$token" ]; then
    code="$(curl --max-time 20 -sS -D "$EVIDENCE/${label}.headers" -o "$EVIDENCE/${label}.body" -w '%{http_code}' -H 'Host: agc-rotation.example.invalid' -H "Authorization: Bearer $token" "http://${FRONT}:8081/?${marker}" || true)"
  else
    code="$(curl --max-time 20 -sS -D "$EVIDENCE/${label}.headers" -o "$EVIDENCE/${label}.body" -w '%{http_code}' -H 'Host: agc-rotation.example.invalid' "http://${FRONT}:8081/?${marker}" || true)"
  fi
  printf '%s' "$code" >"$EVIDENCE/${label}.code"
  echo "$label=$code BODY=$(tr '\n' ' ' <"$EVIDENCE/${label}.body" | head -c 220)"
}

wait_code() {
  local label="$1" token="$2" want="$3" deadline=$((SECONDS+420)) code
  while (( SECONDS < deadline )); do
    request "$label" "$token"
    code="$(cat "$EVIDENCE/${label}.code")"
    if [ "$code" = "$want" ]; then return 0; fi
    sleep 5
  done
  return 1
}

wait_code baseline_no_token "" 200
BASE_CODE="$(cat "$EVIDENCE/baseline_no_token.code")"
echo "BASE_CODE=$BASE_CODE"

cat >/tmp/policy-a.yaml <<EOF
apiVersion: alb.networking.azure.io/v1alpha1
kind: AuthPolicy
metadata:
  name: rotation-gateway-jwt
  namespace: $NS
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: rotation-gw
    namespace: $NS
  jwt:
    issuer: https://issuer.agc-rotation.invalid
    audiences:
    - $AUD1
    jwks:
      remote:
        uri: https://raw.githubusercontent.com/zerodaybugs/runner-cleanroom-20261114-7f3c9a/agc-jwks-rotation-20261122/agc-jwks-rotation-20261122/jwks-a.json
EOF
kubectl apply -f /tmp/policy-a.yaml

wait_policy_generation() {
  local expected="$1" deadline=$((SECONDS+600))
  while (( SECONDS < deadline )); do
    local j gen ok
    j="$(kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o json 2>/dev/null || true)"
    gen="$(jq -r '.metadata.generation // 0' <<<"$j" 2>/dev/null || echo 0)"
    ok="$(jq -r --argjson g "$expected" '
      ([.status.conditions[]?|select(.type=="Accepted" and .status=="True" and (.observedGeneration//0)>=$g)]|length)>0
      and ([.status.conditions[]?|select(.type=="ResolvedRefs" and .status=="True" and (.observedGeneration//0)>=$g)]|length)>0
      and ([.status.conditions[]?|select(.status=="False" and (.observedGeneration//0)>=$g)]|length)==0
    ' <<<"$j" 2>/dev/null || echo false)"
    echo "WAIT_POLICY expected=$expected gen=$gen ok=$ok conditions=$(jq -c '.status.conditions // []' <<<"$j" 2>/dev/null || true)"
    if [ "$gen" -ge "$expected" ] 2>/dev/null && [ "$ok" = "true" ]; then
      sleep 10
      return 0
    fi
    sleep 5
  done
  return 1
}
wait_policy_generation 1
kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o yaml >"$EVIDENCE/policy-gen1.yaml"

wait_code gen1_no_token "" 401
wait_code gen1_token_a "$TOKEN_A" 200
request gen1_token_b "$TOKEN_B"

echo "__ROTATE_URI_TO_B__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl patch authpolicy rotation-gateway-jwt -n "$NS" --type=merge -p '{"spec":{"jwt":{"jwks":{"remote":{"uri":"https://raw.githubusercontent.com/zerodaybugs/runner-cleanroom-20261114-7f3c9a/agc-jwks-rotation-20261122/agc-jwks-rotation-20261122/jwks-b.json"}}}}}'
wait_policy_generation 2
kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o yaml >"$EVIDENCE/policy-gen2.yaml"
wait_code gen2_token_b "$TOKEN_B" 200
request gen2_no_token ""
for i in $(seq 1 8); do request "gen2_old_token_a_${i}" "$TOKEN_A"; sleep 2; done

echo "__ROTATE_AUDIENCE__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl patch authpolicy rotation-gateway-jwt -n "$NS" --type=merge -p '{"spec":{"jwt":{"audiences":["api://agc-rotation-new-audience"],"jwks":{"remote":{"uri":"https://raw.githubusercontent.com/zerodaybugs/runner-cleanroom-20261114-7f3c9a/agc-jwks-rotation-20261122/agc-jwks-rotation-20261122/jwks-a.json"}}}}}'
wait_policy_generation 3
kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o yaml >"$EVIDENCE/policy-gen3.yaml"
wait_code gen3_token_a_aud2 "$TOKEN_A_AUD2" 200
request gen3_old_audience_token_a "$TOKEN_A"
request gen3_wrong_key_token_b "$TOKEN_B"

echo "__ROUTE_OPTOUT_CREATE__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat >/tmp/route-optout.yaml <<EOF
apiVersion: alb.networking.azure.io/v1alpha1
kind: AuthPolicy
metadata:
  name: rotation-route-optout
  namespace: $NS
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: rotation-route
    namespace: $NS
  jwt: {}
EOF
kubectl apply -f /tmp/route-optout.yaml
for _ in $(seq 1 120); do
  j="$(kubectl get authpolicy rotation-route-optout -n "$NS" -o json 2>/dev/null || true)"
  ok="$(jq -r '([.status.conditions[]?|select(.type=="Accepted" and .status=="True")]|length)>0 and ([.status.conditions[]?|select(.status=="False")]|length)==0' <<<"$j" 2>/dev/null || echo false)"
  [ "$ok" = true ] && break
  sleep 3
done
wait_code optout_no_token "" 200
kubectl get authpolicy rotation-route-optout -n "$NS" -o yaml >"$EVIDENCE/route-optout.yaml"

echo "__ROUTE_OPTOUT_DELETE__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl delete authpolicy rotation-route-optout -n "$NS" --wait=true
wait_code post_delete_no_token "" 401
wait_code post_delete_token_a_aud2 "$TOKEN_A_AUD2" 200

echo "__INVALID_JWKS_OBSERVATION__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if kubectl patch authpolicy rotation-gateway-jwt -n "$NS" --type=merge -p '{"spec":{"jwt":{"jwks":{"remote":{"uri":"https://127.0.0.1.invalid/jwks.json"}}}}}'; then
  printf 'true' >"$EVIDENCE/invalid-jwks-patch-applied.txt"
else
  printf 'false' >"$EVIDENCE/invalid-jwks-patch-applied.txt"
fi
sleep 20
kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o yaml >"$EVIDENCE/policy-invalid-jwks.yaml" || true
kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o json | jq '{generation:.metadata.generation,spec:.spec,status:.status}' >"$EVIDENCE/policy-invalid-jwks.json" || true
for i in $(seq 1 6); do request "invalid_jwks_token_${i}" "$TOKEN_A_AUD2"; sleep 3; done

echo "__RESTORE_GEN__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl patch authpolicy rotation-gateway-jwt -n "$NS" --type=merge -p '{"spec":{"jwt":{"jwks":{"remote":{"uri":"https://raw.githubusercontent.com/zerodaybugs/runner-cleanroom-20261114-7f3c9a/agc-jwks-rotation-20261122/agc-jwks-rotation-20261122/jwks-a.json"}}}}}'
RESTORE_GEN="$(kubectl get authpolicy rotation-gateway-jwt -n "$NS" -o jsonpath='{.metadata.generation}')"
wait_policy_generation "$RESTORE_GEN"
wait_code restore_token_a_aud2 "$TOKEN_A_AUD2" 200
request restore_no_token ""

kubectl get authpolicy,gateway,httproute -n "$NS" -o yaml >"$EVIDENCE/final-state.yaml"
kubectl logs -n "$NS" deployment/rotation-backend --since=60m >"$EVIDENCE/backend.log" 2>&1 || true
kubectl get events -n "$NS" --sort-by=.lastTimestamp >"$EVIDENCE/events.txt" || true

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON_BIN" ]; then
  echo "PYTHON_NOT_FOUND" >&2
  exit 41
fi
"$PYTHON_BIN" - "$EVIDENCE" <<'PY'
import json, pathlib, sys
d=pathlib.Path(sys.argv[1])
def code(name):
    p=d/(name+".code")
    return p.read_text().strip() if p.exists() else "MISSING"
matrix={
  "baseline_no_token":code("baseline_no_token"),
  "gen1_no_token":code("gen1_no_token"),
  "gen1_token_a":code("gen1_token_a"),
  "gen1_token_b":code("gen1_token_b"),
  "gen2_token_b":code("gen2_token_b"),
  "gen2_no_token":code("gen2_no_token"),
  "gen2_old_token_a":[code(f"gen2_old_token_a_{i}") for i in range(1,9)],
  "gen3_token_a_aud2":code("gen3_token_a_aud2"),
  "gen3_old_audience_token_a":code("gen3_old_audience_token_a"),
  "gen3_wrong_key_token_b":code("gen3_wrong_key_token_b"),
  "optout_no_token":code("optout_no_token"),
  "post_delete_no_token":code("post_delete_no_token"),
  "post_delete_token_a_aud2":code("post_delete_token_a_aud2"),
  "invalid_jwks_patch_applied":(d/"invalid-jwks-patch-applied.txt").read_text().strip() if (d/"invalid-jwks-patch-applied.txt").exists() else "MISSING",
  "invalid_jwks_token":[code(f"invalid_jwks_token_{i}") for i in range(1,7)],
  "restore_token_a_aud2":code("restore_token_a_aud2"),
  "restore_no_token":code("restore_no_token"),
}
vulnerabilities=[]
if "200" in matrix["gen2_old_token_a"]:
    vulnerabilities.append("OLD_JWKS_KEY_ACCEPTED_AFTER_NEW_KEY_ACTIVE")
if matrix["gen3_old_audience_token_a"]=="200":
    vulnerabilities.append("OLD_AUDIENCE_ACCEPTED_AFTER_NEW_AUDIENCE_ACTIVE")
if matrix["post_delete_no_token"]=="200":
    vulnerabilities.append("DELETED_ROUTE_OPTOUT_REMAINS_PUBLIC")
# Invalid-JWKS behavior is evidence-only. Retaining last-known-good configuration
# can be a deliberate availability/security tradeoff; it is not auto-routed.
expected={
  "baseline_no_token":{"200"},
  "gen1_no_token":{"401"},
  "gen1_token_a":{"200"},
  "gen1_token_b":{"401","403"},
  "gen2_token_b":{"200"},
  "gen2_no_token":{"401"},
  "gen3_token_a_aud2":{"200"},
  "gen3_old_audience_token_a":{"401","403"},
  "gen3_wrong_key_token_b":{"401","403"},
  "optout_no_token":{"200"},
  "post_delete_no_token":{"401"},
  "post_delete_token_a_aud2":{"200"},
  "restore_token_a_aud2":{"200"},
  "restore_no_token":{"401"},
}
mismatches={
  k:{"got":matrix[k],"want":sorted(v)}
  for k,v in expected.items()
  if matrix.get(k) not in v
}
result={"matrix":matrix,"vulnerabilities":vulnerabilities,"expected_mismatches":mismatches,
        "verdict":"CANDIDATE" if vulnerabilities else ("SECURE" if not mismatches else "INCONCLUSIVE")}
(d/"matrix.json").write_text(json.dumps(result,indent=2))
print("__MATRIX_JSON__")
print(json.dumps(result,indent=2))
PY

sha256sum "$EVIDENCE"/* >"$EVIDENCE/SHA256SUMS.txt" || true
echo "__RUN_END__ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
