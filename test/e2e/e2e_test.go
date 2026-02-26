//go:build e2e
// +build e2e

/*
Copyright 2025.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/openshift/external-secrets-operator/test/utils"
)

//go:embed testdata/*
var testassets embed.FS

const (
	// test bindata
	externalSecretsFile     = "testdata/external_secret.yaml"
	expectedSecretValueFile = "testdata/expected_value.yaml"
)

const (
	// test resource names
	operatorNamespace              = "external-secrets-operator"
	operandNamespace               = "external-secrets"
	operatorPodPrefix              = "external-secrets-operator-controller-manager-"
	operandCoreControllerPodPrefix = "external-secrets-"
	operandCertControllerPodPrefix = "external-secrets-cert-controller-"
	operandWebhookPodPrefix        = "external-secrets-webhook-"
	testNamespacePrefix            = "external-secrets-e2e-test-"
	vaultNamespace                 = "vault-test"
	vaultManifestFile              = "testdata/vault/vault.yaml"
	vaultServiceName               = "vault"
	vaultNetworkPolicyFile         = "testdata/vault/vault-networkpolicy.yaml"
	vaultAddr                      = "http://vault.vault-test.svc.cluster.local:8200"
)

const (
	externalSecretsGroupName = "external-secrets.io"
	v1APIVersion             = "v1"
	v1alpha1APIVersion       = "v1alpha1"
	clusterSecretStoresKind  = "clustersecretstores"
	secretStoresKind         = "secretstores"
	PushSecretsKind          = "pushsecrets"
	externalSecretsKind      = "externalsecrets"
)

var _ = Describe("External Secrets Operator End-to-End test scenarios", Ordered, func() {
	ctx := context.TODO()
	var (
		clientset           *kubernetes.Clientset
		dynamicClient       *dynamic.DynamicClient
		loader              utils.DynamicResourceLoader
		awsSecretName       string
		testNamespace       string
		expectedSecretValue []byte
	)

	BeforeAll(func() {
		var err error
		loader = utils.NewDynamicResourceLoader(ctx, &testing.T{})

		clientset, err = kubernetes.NewForConfig(cfg)
		Expect(err).Should(BeNil())

		dynamicClient, err = dynamic.NewForConfig(cfg)
		Expect(err).Should(BeNil())

		awsSecretName = fmt.Sprintf("eso-e2e-secret-%s", utils.GetRandomString(5))

		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"e2e-test": "true",
					"operator": "openshift-external-secrets-operator",
				},
				GenerateName: testNamespacePrefix,
			},
		}
		By("Creating the test namespace")
		got, err := clientset.CoreV1().Namespaces().Create(context.Background(), namespace, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")
		testNamespace = got.GetName()

		By("Waiting for operator pod to be ready")
		Expect(utils.VerifyPodsReadyByPrefix(ctx, clientset, operatorNamespace, []string{
			operatorPodPrefix,
		})).To(Succeed())

		By("Creating the externalsecrets.openshift.operator.io/cluster CR")
		loader.CreateFromFile(testassets.ReadFile, externalSecretsFile, "")
	})

	AfterAll(func() {
		By("Deleting the externalsecrets.openshift.operator.io/cluster CR")
		loader.DeleteFromFile(testassets.ReadFile, externalSecretsFile, "")

		By("Deleting the test namespace")
		Expect(clientset.CoreV1().Namespaces().Delete(ctx, testNamespace, metav1.DeleteOptions{})).
			NotTo(HaveOccurred(), "failed to delete test namespace")
	})

	BeforeEach(func() {
		By("Verifying external-secrets operand pods are ready")
		Expect(utils.VerifyPodsReadyByPrefix(ctx, clientset, operandNamespace, []string{
			operandCoreControllerPodPrefix,
			operandCertControllerPodPrefix,
			operandWebhookPodPrefix,
		})).To(Succeed())
	})

	Context("AWS Secret Manager", Label("Platform:AWS"), func() {
		const (
			clusterSecretStoreFile           = "testdata/aws_secret_store.yaml"
			externalSecretFile               = "testdata/aws_external_secret.yaml"
			pushSecretFile                   = "testdata/push_secret.yaml"
			awsSecretToPushFile              = "testdata/aws_k8s_push_secret.yaml"
			awsSecretNamePattern             = "${AWS_SECRET_KEY_NAME}"
			awsSecretValuePattern            = "${SECRET_VALUE}"
			awsClusterSecretStoreNamePattern = "${CLUSTERSECRETSTORE_NAME}"
			awsSecretRegionName              = "ap-south-1"
		)

		AfterAll(func() {
			By("Deleting the AWS secret")
			Expect(utils.DeleteAWSSecret(ctx, clientset, awsSecretName, awsSecretRegionName)).
				NotTo(HaveOccurred(), "failed to delete AWS secret test/e2e")
		})

		It("should create secrets mentioned in ExternalSecret using the referenced ClusterSecretStore", func() {
			var (
				clusterSecretStoreResourceName = fmt.Sprintf("aws-secret-store-%s", utils.GetRandomString(5))
				pushSecretResourceName         = "aws-push-secret"
				externalSecretResourceName     = "aws-external-secret"
				secretResourceName             = "aws-secret"
				keyNameInSecret                = "aws_secret_access_key"
			)

			defer func() {
				Expect(utils.DeleteAWSSecret(ctx, clientset, awsSecretName, awsSecretRegionName)).
					NotTo(HaveOccurred(), "failed to delete AWS secret test/e2e")
			}()

			expectedSecretValue, err := utils.ReadExpectedSecretValue(expectedSecretValueFile)
			Expect(err).To(Succeed())

			By("Creating kubernetes secret to be used in PushSecret")
			secretsAssetFunc := utils.ReplacePatternInAsset(awsSecretValuePattern, base64.StdEncoding.EncodeToString(expectedSecretValue))
			loader.CreateFromFile(secretsAssetFunc, awsSecretToPushFile, testNamespace)
			defer loader.DeleteFromFile(testassets.ReadFile, awsSecretToPushFile, testNamespace)

			By("Creating ClusterSecretStore")
			cssAssetFunc := utils.ReplacePatternInAsset(awsClusterSecretStoreNamePattern, clusterSecretStoreResourceName)
			loader.CreateFromFile(cssAssetFunc, clusterSecretStoreFile, testNamespace)
			defer loader.DeleteFromFile(cssAssetFunc, clusterSecretStoreFile, testNamespace)

			By("Waiting for ClusterSecretStore to become Ready")
			Expect(utils.WaitForESOResourceReady(ctx, dynamicClient,
				schema.GroupVersionResource{
					Group:    externalSecretsGroupName,
					Version:  v1APIVersion,
					Resource: clusterSecretStoresKind,
				},
				"", clusterSecretStoreResourceName, time.Minute,
			)).To(Succeed())

			By("Creating PushSecret")
			assetFunc := utils.ReplacePatternInAsset(awsSecretNamePattern, awsSecretName,
				awsClusterSecretStoreNamePattern, clusterSecretStoreResourceName)
			loader.CreateFromFile(assetFunc, pushSecretFile, testNamespace)
			defer loader.DeleteFromFile(testassets.ReadFile, pushSecretFile, testNamespace)

			By("Waiting for PushSecret to become Ready")
			Expect(utils.WaitForESOResourceReady(ctx, dynamicClient,
				schema.GroupVersionResource{
					Group:    externalSecretsGroupName,
					Version:  v1alpha1APIVersion,
					Resource: PushSecretsKind,
				},
				testNamespace, pushSecretResourceName, time.Minute,
			)).To(Succeed())

			By("Creating ExternalSecret")
			loader.CreateFromFile(assetFunc, externalSecretFile, testNamespace)
			defer loader.DeleteFromFile(testassets.ReadFile, externalSecretFile, testNamespace)

			By("Waiting for ExternalSecret to become Ready")
			Expect(utils.WaitForESOResourceReady(ctx, dynamicClient,
				schema.GroupVersionResource{
					Group:    externalSecretsGroupName,
					Version:  v1APIVersion,
					Resource: externalSecretsKind,
				},
				testNamespace, externalSecretResourceName, time.Minute,
			)).To(Succeed())

			By("Waiting for target secret to be created with expected data")
			Eventually(func(g Gomega) {
				secret, err := loader.KubeClient.CoreV1().Secrets(testNamespace).Get(ctx, secretResourceName, metav1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred(), "should get %s from namespace %s", secretResourceName, testNamespace)

				val, ok := secret.Data[keyNameInSecret]
				g.Expect(ok).To(BeTrue(), "%s should be present in secret %s", keyNameInSecret, secret.Name)

				g.Expect(val).To(Equal(expectedSecretValue), "%s does not match expected value", keyNameInSecret)
			}, time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	// TODO: Update vault.yaml
	Context("Vault Secret Manager", Label("Platform:Vault"), func() {
		const (
			clusterSecretStoreFile = "testdata/vault/secret_store.yaml"
			externalSecretFile     = "testdata/vault/external_secret.yaml"
			vaultSecretName        = "foo"
			vaultSecretKey         = "my-value"
			vaultSecretValue       = "bar"
		)

		_ = expectedSecretValue

		BeforeAll(func() {
			By("Deploying Vault")
			Expect(applyVault(ctx, loader)).To(Succeed())

			By("Waiting for Vault pod")
			Expect(waitForVaultPod(ctx, clientset)).To(Succeed())

			By("Initializing and unsealing Vault")
			token, err := initAndUnsealVault(ctx, clientset)
			Expect(err).ToNot(HaveOccurred())

			By("Enable KV Engine")
			Expect(enableKVEngine(ctx, clientset, token)).To(Succeed())

			By("Create test secret in vault")
			Expect(createVaultTestSecret(
				ctx,
				clientset,
				token,
				vaultSecretName,
				vaultSecretKey,
				vaultSecretValue,
			)).To(Succeed())

			By("Creating vault-token Secret")
			Expect(createVaultTokenSecret(ctx, clientset, token)).To(Succeed())

		})

		AfterEach(func() {
			By("Cleaning up ExternalSecret")
			safeDelete(exec.Command("oc", "delete", "externalsecret", "vault-e2e-test", "-n", vaultNamespace, "--ignore-not-found"))

			By("Cleaning up SecretStore")
			safeDelete(exec.Command("oc", "delete", "secretstore", "vault-store", "-n", vaultNamespace, "--ignore-not-found"))

			By("Cleaning up generated Secret")
			safeDelete(exec.Command("oc", "delete", "secret", "vault-secret", "-n", vaultNamespace, "--ignore-not-found"))

			By("Cleaning up vault-token secret")
			safeDelete(exec.Command("oc", "delete", "secret", "vault-token", "-n", vaultNamespace, "--ignore-not-found"))

			By("Cleaning up NetworkPolicy")
			safeDelete(exec.Command("oc", "delete", "-f", vaultNetworkPolicyFile, "--ignore-not-found"))

			By("Cleaning up ExternalSecretsConfig")
			safeDelete(exec.Command("oc", "delete", "-f", "testdata/vault/externalsecretsconfig.yaml", "--ignore-not-found"))
		})

		It("should create secret mentioned in ExternalSecret using the referenced SecretStore", func() {
			var (
				// test bindata for Vault
				externalsecretsConfigFile  = "testdata/vault/externalsecretsconfig.yaml"
				vaultSecretStoreFile       = "testdata/vault/cluster_secret_store.yaml"
				vaultExternalSecretFile    = "testdata/vault/external_secret.yaml"
				secretStoreResourceName    = "vault-backend"
				externalSecretResourceName = "vault-example"
				targetSecretName           = "k8s-secret-to-create" //must match with external_secret.yaml target.name
				targetSecretKey            = "password"             //must match with external_secret.yaml data.secretKey
			)

			// defer func() {
			// }()

			By("Applying ExternalSecretsConfig")
			cmd := exec.Command("oc", "apply", "-f", externalsecretsConfigFile)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(out))

			By("Applying Vault NetworkPolicy")
			cmd = exec.Command("oc", "apply", "-f", vaultNetworkPolicyFile)
			out, err = cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(out))

			By("Creating SecretStore")
			cmd = exec.Command(
				"oc", "apply", "-f", vaultSecretStoreFile, "-n", vaultNamespace,
			)
			out, err = cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(out))

			By("Waiting for SecretStore to become Ready")
			Expect(utils.WaitForESOResourceReady(ctx, dynamicClient,
				schema.GroupVersionResource{
					Group:    externalSecretsGroupName,
					Version:  v1APIVersion,
					Resource: secretStoresKind,
				},
				"", secretStoreResourceName, time.Minute,
			)).To(Succeed())

			By("Creating ExternalSecret")
			cmd = exec.Command(
				"oc", "apply", "-f", vaultExternalSecretFile, "-n", vaultNamespace,
			)
			output, err = cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(output))

			By("Waiting for ExternalSecret to become Ready")
			Expect(utils.WaitForESOResourceReady(ctx, dynamicClient,
				schema.GroupVersionResource{
					Group:    externalSecretsGroupName,
					Version:  v1APIVersion,
					Resource: externalSecretsKind,
				},
				vaultNamespace, externalSecretResourceName, time.Minute,
			)).To(Succeed())

			By("Verifying the generated Kubernetes Secret contains expected value")
			Eventually(func(g Gomega) {
				secret, err := clientset.CoreV1().
					Secrets(vaultNamespace).
					Get(ctx, targetSecretName, metav1.GetOptions{})

				g.Expect(err).NotTo(HaveOccurred(),
					"Expected secret %s to exist in namespace %s",
					targetSecretName, vaultNamespace)

				value, exists := secret.Data[targetSecretKey]
				g.Expect(exists).To(BeTrue(),
					"Expected key %s in secret %s",
					targetSecretKey, targetSecretName)

				g.Expect(string(value)).To(Equal(vaultSecretValue),
					"Secret value mismatch")

			}, time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// Apply vault manifest
func applyVault(ctx context.Context, loader utils.DynamicResourceLoader) error {

	cmd := exec.CommandContext(ctx,
		"oc",
		"apply",
		"-f",
		vaultManifestFile,
	)

	out, err := cmd.CombinedOutput()
	fmt.Println(string(out))

	if err != nil {
		return fmt.Errorf("Failed to apply vault manifest: %w", err)
	}

	return nil
}

// wait for vault pod
func waitForVaultPod(ctx context.Context, client *kubernetes.Clientset) error {
	return utils.VerifyPodsReadyByPrefix(
		ctx,
		client,
		vaultNamespace,
		[]string{"vault"},
	)
}

// initAndUnsealVault initializes and unselas the Vault instance running in the test namespace, then returns the generated root token.
// it executes the vault CLI commands inside the vault pod and extracts the unseal key and root token from the output,
// and prepares vault for further configuration in E2E tests.
func initAndUnsealVault(ctx context.Context, client *kubernetes.Clientset) (string, error) {
	podName, err := getVaultPodName(ctx, client)
	if err != nil {
		return "", err
	}

	cmd := exec.Command(
		"oc", "exec", "-n", vaultNamespace, podName, "--", "sh", "-c",
		`
vault operator init -key-shares=1 -key-threshold=1 > /tmp/init.out &&
UNSEAL_KEY=$(grep 'Unseal Key 1:' /tmp/init.out | awk '{print $NF}') &&
ROOT_TOKEN=$(grep 'Initial Root Token:' /tmp/init.out | awk '{print $NF}') &&
vault operator unseal $UNSEAL_KEY &&
vault status &&
vault login $ROOT_TOKEN &&
echo $ROOT_TOKEN
		`,
	)

	out, err := utils.Run(cmd)
	fmt.Println(string(out))
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	token := strings.TrimSpace(lines[len(lines)-1])
	fmt.Println("Vault Token: ", token)
	return token, nil
}

func getVaultPodName(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	pods, err := clientset.CoreV1().
		Pods(vaultNamespace).
		List(ctx, metav1.ListOptions{
			LabelSelector: "app=vault",
		})
	if err != nil {
		return "", err
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			return pod.Name, nil
		}
	}
	return "", fmt.Errorf("no running vault pod found")
}

// Enable KV engine
func enableKVEngine(ctx context.Context, client *kubernetes.Clientset, token string) error {
	podName, err := getVaultPodName(ctx, client)
	if err != nil {
		return err
	}

	cmd := exec.Command(
		"oc", "exec", "-n", vaultNamespace, podName, "--", "sh", "-c",
		fmt.Sprintf(
			"vault status && vault login %s && vault secrets enable -path=secret kv-v2 || true",
			token,
		),
	)

	out, err := utils.Run(cmd)
	fmt.Println(string(out))
	return err
}

// Create Vault policy
func createVaultPolicy(ctx context.Context, client *kubernetes.Clientset, token string) error {
	podName, err := getVaultPodName(ctx, client)
	if err != nil {
		return err
	}
	policy := `
path "secret/data/*" {
  capabilities = ["read"]
}

path "secret/metadata/*" {
   capabilities = ["read"]
 }
`
	cmd := exec.Command(
		"oc", "exec", "-n", vaultNamespace, podName, "--", "sh", "-c",
		fmt.Sprintf(`
cat <<EOF > /tmp/eso-policy.hcl
%s
EOF
vault policy write eso-policy /tmp/eso-policy.hcl
`, token, policy),
	)

	out, err := utils.Run(cmd)
	fmt.Println(string(out))
	return err
}

// Create a vault test secret
func createVaultTestSecret(ctx context.Context, client *kubernetes.Clientset, token string, secretname string, key, value string) error {
	podName, err := getVaultPodName(ctx, client)
	if err != nil {
		return err
	}

	cmd := exec.Command(
		"oc", "exec", "-n", vaultNamespace, podName, "--", "sh", "-c",
		fmt.Sprintf(
			"vault kv put secret/%s %s=\"%s\"",
			secretname, key, value,
		),
	)

	out, err := utils.Run(cmd)
	fmt.Println(string(out))
	return err
}

func createVaultTokenSecret(ctx context.Context, client *kubernetes.Clientset, token string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: vaultNamespace,
		},
		StringData: map[string]string{
			"token": token,
		},
	}

	_, err := client.CoreV1().Secrets(vaultNamespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

func safeDelete(cmd *exec.Cmd) {
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Cleanup error:", string(out))
	}
}
