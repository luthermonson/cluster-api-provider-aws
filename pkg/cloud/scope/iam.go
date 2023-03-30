package scope

import "sigs.k8s.io/cluster-api-provider-aws/pkg/cloud"

// IAMScope is the interface for the scope to be used with the IAM service.
type IAMScope interface {
	cloud.ClusterScoper
}
