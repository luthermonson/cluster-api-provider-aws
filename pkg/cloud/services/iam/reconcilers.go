package iam

import (
	"context"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	v1certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"

	"sigs.k8s.io/cluster-api-provider-aws/v2/cmd/clusterawsadm/converters"
	"sigs.k8s.io/cluster-api/api/v1beta1"
)

// reconcilePodIdentityWebhook generates certs and starts the webhook in the workload cluster
// https://github.com/aws/amazon-eks-pod-identity-webhook
// 1. generate webhook certs via cert-manager in the management cluster
// 2. push cert secret down to the workload cluster
// 3. deploy pod identity webhook components with mounted certs (rbac,deployment,mwh,service)
func (s *Service) reconcilePodIdentityWebhook(ctx context.Context) error {
	certName := fmt.Sprintf(PodIdentityWebhookCertificateFormat, s.scope.Name())
	certSecret, err := certificateSecret(ctx,
		certName, s.scope.Namespace(),
		fmt.Sprintf(SelfsignedIssuerFormat, s.scope.Name()), []string{
			fmt.Sprintf("%s.%s.svc", podIdentityWebhookName, podIdentityWebhookNamespace),
			fmt.Sprintf("%s.%s.svc.cluster.local", podIdentityWebhookName, podIdentityWebhookNamespace),
		}, s.scope.ManagementClient())

	if err != nil {
		return err
	}

	remoteClient, err := s.scope.RemoteClient()
	if err != nil {
		return err
	}

	// switch it to kube-system and move it to the remote cluster
	certSecret.Name = podIdentityWebhookName
	certSecret.Namespace = podIdentityWebhookNamespace
	if err := reconcileCertifcateSecret(ctx, certSecret, remoteClient); err != nil {
		return err
	}

	if err := reconcilePodIdentityWebhookComponents(ctx, certSecret, remoteClient); err != nil {
		return err
	}

	return nil
}

// reconcileSelfsignedIssuer create a selfsigned issuer at the cluster level
func (s *Service) reconcileSelfsignedIssuer(ctx context.Context) error {
	mgmtClient := s.scope.ManagementClient()
	issuerName := fmt.Sprintf(SelfsignedIssuerFormat, s.scope.Name())
	issuer := &v1certmanager.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				v1beta1.ProviderNameLabel: "infrastructure-aws",
			},
			Name:      issuerName,
			Namespace: s.scope.Namespace(),
		},
		Spec: v1certmanager.IssuerSpec{
			IssuerConfig: v1certmanager.IssuerConfig{
				SelfSigned: &v1certmanager.SelfSignedIssuer{},
			},
		},
	}

	if err := mgmtClient.Get(ctx, types.NamespacedName{
		Name:      issuerName,
		Namespace: s.scope.Namespace(),
	}, issuer); err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if issuer.UID != "" {
		return nil
	}

	return mgmtClient.Create(ctx, issuer)
}

// CreateOIDCProvider will create an OIDC provider.
func (s *Service) reconcileIdentityProvider(ctx context.Context) error {
	s3Host := fmt.Sprintf(S3HostFormat, s.scope.Region())
	thumbprint, err := fetchRootCAThumbprint(s3Host, 443)
	if err != nil {
		return err
	}

	oidcURL := "https://" + path.Join(s3Host, s.scope.Bucket().Name)
	arn, err := findAndVerifyOIDCProvider(oidcURL, thumbprint, s.IAMClient)
	if err != nil {
		return err
	}

	if arn != "" {
		return nil
	}

	var tags []*iam.Tag
	tags = append(tags, &iam.Tag{
		Key:   aws.String(v1beta2.ClusterAWSCloudProviderTagKey(s.scope.Name())),
		Value: aws.String(string(v1beta2.ResourceLifecycleOwned)),
	})

	input := iam.CreateOpenIDConnectProviderInput{
		ClientIDList:   aws.StringSlice([]string{STSAWSAudience}),
		ThumbprintList: aws.StringSlice([]string{thumbprint}),
		Url:            aws.String(oidcURL),
		Tags:           tags,
	}
	providerStatus := s.scope.OIDCProviderStatus()
	provider, err := s.IAMClient.CreateOpenIDConnectProvider(&input)
	if err != nil {
		return errors.Wrap(err, "error creating provider")
	}

	providerStatus.ARN = aws.StringValue(provider.OpenIDConnectProviderArn)
	oidcTrustPolicy := buildOIDCTrustPolicy(providerStatus.ARN)
	policy, err := converters.IAMPolicyDocumentToJSON(oidcTrustPolicy)
	if err != nil {
		return errors.Wrap(err, "failed to parse IAM policy")
	}
	providerStatus.TrustPolicy = whitespaceRe.ReplaceAllString(policy, "")
	return s.scope.PatchObject()
}

// reconcileTrustPolicyConfigMap make sure the remote cluster has the config map of the trust policy, this enables
// the remote cluster to have everything it needs to create roles for services accounts.
func (s *Service) reconcileTrustPolicyConfigMap(ctx context.Context) error {
	remoteClient, err := s.scope.RemoteClient()
	if err != nil {
		return err
	}

	configMapRef := types.NamespacedName{
		Name:      trustPolicyConfigMapName,
		Namespace: trustPolicyConfigMapNamespace,
	}

	trustPolicyConfigMap := &corev1.ConfigMap{}
	err = remoteClient.Get(ctx, configMapRef, trustPolicyConfigMap)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("getting %s/%s config map: %w", trustPolicyConfigMapNamespace, trustPolicyConfigMapName, err)
	}

	policy, err := converters.IAMPolicyDocumentToJSON(buildOIDCTrustPolicy(s.scope.OIDCProviderStatus().ARN))
	if err != nil {
		return errors.Wrap(err, "failed to parse IAM policy")
	}

	trustPolicyConfigMap.Data = map[string]string{
		TrustPolicyJSON: policy,
	}

	if trustPolicyConfigMap.UID == "" {
		trustPolicyConfigMap.Name = trustPolicyConfigMapName
		trustPolicyConfigMap.Namespace = trustPolicyConfigMapNamespace
		return remoteClient.Create(ctx, trustPolicyConfigMap)
	}

	return remoteClient.Update(ctx, trustPolicyConfigMap)
}
