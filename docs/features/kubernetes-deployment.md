# Kubernetes deployment

NetWatcher includes Kustomize manifests under `deploy/kubernetes/` for running the pipeline in a cluster.

## Apply

```bash
make k8s-apply
# equivalent: kubectl apply -k deploy/kubernetes/
```

Delete:

```bash
make k8s-delete
```

## Layout

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | `netwatcher` namespace |
| `configmap.yaml` | Shared configuration |
| `kafka.yaml` | Kafka broker |
| `elasticsearch-kibana.yaml` | ES and Kibana |
| `rust-services.yaml` | Gateway, enricher, indexer, MCP |
| `capture-daemonset.yaml` | Capture agents on every node |
| `kustomization.yaml` | Bundle and image tags |

## Capture DaemonSet

Capture agents deploy as a `DaemonSet` with host networking so they can bind to node interfaces. Each pod needs `CAP_NET_RAW` and `CAP_NET_ADMIN` (configured in the manifest).

## Images

CI publishes container images to GHCR. Update image references in `deploy/kubernetes/` to match your registry and tag after CI builds.

Example workflow: `.github/workflows/container.yml`

## Verification

The repo includes a manifest validation step in `scripts/verify-stack.sh`:

```bash
docker run --rm -v "$(pwd)/deploy/kubernetes:/work" -w /work \
  alpine/k8s:1.30.2 kustomize build . >/dev/null
```

## Related

- [Getting started](../getting-started.md)
- [Capture agent](capture-agent.md)
- [Architecture](../architecture.md)
