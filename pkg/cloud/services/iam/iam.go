package iam

import (
	"context"
	"errors"
	"regexp"

	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/s3"
)

type Service struct {
	scope     scope.EC2Scope
	IAMClient iamiface.IAMAPI
}

// NewService returns a new service given the api clients.
func NewService(clusterScope scope.EC2Scope) *Service {
	iamClient := scope.NewIAMClient(clusterScope, clusterScope, clusterScope, clusterScope.InfraCluster())

	return &Service{
		scope:     clusterScope,
		IAMClient: iamClient,
	}
}

const (
	TrustPolicyJSON                     = "trust-policy.json"
	PodIdentityWebhookCertificateFormat = "%s-pod-id-wh"
	SelfsignedIssuerFormat              = "%s-selfsigned-issuer"
	S3HostFormat                        = "s3-%s.amazonaws.com"
	STSAWSAudience                      = "sts.amazonaws.com"
	trustPolicyConfigMapName            = "boilerplate-oidc-trust-policy"
	trustPolicyConfigMapNamespace       = metav1.NamespaceDefault
)

var (
	whitespaceRe = regexp.MustCompile(`(?m)[\t\n]`)
)

// ReconcileOIDCProvider replicates functionality already built into managed clusters by auto-deploying the
// modifying kube-apiserver args, deploying the pod identity webhook and setting/configuring an oidc provider
// for more details see: https://github.com/aws/amazon-eks-pod-identity-webhook/blob/master/SELF_HOSTED_SETUP.md
// 1. create a self signed issuer for the mutating webhook
// 2. add create a json patch for kube-apiserver and use capi config to add to the kubeadm.yml
// 3. create an oidc provider in aws which points to the s3 bucket
// 4. pause until kubeconfig and cluster acccess is ready
// 5. move openid config and jwks to the s3 bucket
// 6. add the pod identity webhook to the workload cluster
// 7. add the configmap to the workload cluster
func (s *Service) ReconcileOIDCProvider() error {
	if !s.scope.AssociateOIDCProvider() {
		return nil
	}

	log := s.scope.GetLogger()
	log.Info("Associating OIDC Provider")

	if s.scope.Bucket() == nil {
		return errors.New("s3 bucket configuration required to associate oidc provider")
	}

	// TODO bring in the ctx to reconcileNormal and pass it thru
	ctx := context.Background()
	if err := s.reconcileSelfsignedIssuer(ctx); err != nil {
		return err
	}

	if err := s.reconcileKubeAPIParameters(ctx); err != nil {
		return err
	}

	if err := s.reconcileIdentityProvider(ctx); err != nil {
		return err
	}

	// the following can only run with a working workload cluster, return nil until then
	_, ok := s.scope.InfraCluster().GetAnnotations()[scope.KubeconfigReadyAnnotation]
	if !ok {
		log.Info("Associating OIDC Provider paused, kubeconfig and workload cluster API access is not ready")
		return nil
	}

	log.Info("Associating OIDC Provider continuing, kubeconfig for the workload cluster is available")
	if err := s.reconcileBucketContents(ctx); err != nil {
		return err
	}

	if err := s.reconcilePodIdentityWebhook(ctx); err != nil {
		return err
	}

	return s.reconcileTrustPolicyConfigMap(ctx)
}

// DeleteOIDCProvider will delete the iam resources note that the bucket is cleaned up in the s3 service
// 1. delete oidc provider
// 2. delete mwh certificate
// 3. delete cert-manager issuer
func (s *Service) DeleteOIDCProvider(ctx context.Context) error {
	if !s.scope.AssociateOIDCProvider() {
		return nil
	}

	log := s.scope.GetLogger()
	log.Info("Deleting OIDC Provider")

	if s.scope.Bucket() != nil {
		if err := deleteBucketContents(s3.NewService(s.scope)); err != nil {
			return err
		}
	}

	if err := deleteCertificatesAndIssuer(ctx, s.scope.Name(), s.scope.Namespace(), s.scope.ManagementClient()); err != nil {
		return err
	}

	return deleteOIDCProvider(s.scope.OIDCProviderStatus().ARN, s.IAMClient)
}
