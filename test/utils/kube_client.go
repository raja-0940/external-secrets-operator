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

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"
)

// PodExecOptions contains options for executing commands in a pod
type PodExecOptions struct {
	Namespace     string
	PodName       string
	ContainerName string // Optional: leave empty for default container
	Command       []string
	Stdin         io.Reader // Optional: for interactive commands
}

func NewClientsConfigForTest(t *testing.T) (kubernetes.Interface, dynamic.Interface) {
	config, err := GetConfigForTest(t)
	if err == nil {
		t.Logf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	kubeClient, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	dynamicKubeConfig, err := dynamic.NewForConfig(config)
	require.NoError(t, err)
	return kubeClient, dynamicKubeConfig
}

func GetConfigForTest(t *testing.T) (*rest.Config, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: api.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		t.Logf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	return config, err
}

// ExecCommandInPod executes a command in a pod using client-go's remotecommand
// Returns stdout, stderr, and error
func ExecCommandInPod(ctx context.Context, client kubernetes.Interface, config *rest.Config, opts PodExecOptions) (string, string, error) {
	if len(opts.Command) == 0 {
		return "", "", fmt.Errorf("command cannot be empty")
	}

	// Prepare the API request
	req := client.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(opts.PodName).
		Namespace(opts.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: opts.ContainerName,
			Command:   opts.Command,
			Stdin:     opts.Stdin != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kubescheme.ParameterCodec)

	// Create the executor
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("failed to create executor: %w", err)
	}

	// Prepare buffers for stdout and stderr
	var stdout, stderr bytes.Buffer

	// Execute the command
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  opts.Stdin,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	return stdout.String(), stderr.String(), err
}

// ApplyManifestFromFile applies Kubernetes manifests from a YAML file using dynamic client
// This is a client-go alternative to "kubectl apply -f"
func ApplyManifestFromFile(ctx context.Context, dynamicClient dynamic.Interface, filePath string) error {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read manifest file: %w", err)
	}

	// Split YAML documents
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)

	for {
		var obj unstructured.Unstructured
		if err := decoder.Decode(&obj); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to decode manifest: %w", err)
		}

		// Skip empty documents
		if obj.Object == nil {
			continue
		}

		// Get GVR (GroupVersionResource) from the object
		gvk := obj.GroupVersionKind()
		gvr := schema.GroupVersionResource{
			Group:    gvk.Group,
			Version:  gvk.Version,
			Resource: pluralizeResource(gvk.Kind),
		}

		namespace := obj.GetNamespace()
		name := obj.GetName()

		// Try to get the resource first
		var resourceClient dynamic.ResourceInterface
		if namespace != "" {
			resourceClient = dynamicClient.Resource(gvr).Namespace(namespace)
		} else {
			resourceClient = dynamicClient.Resource(gvr)
		}

		existing, err := resourceClient.Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			// Resource exists, update it
			obj.SetResourceVersion(existing.GetResourceVersion())
			_, err = resourceClient.Update(ctx, &obj, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update %s/%s: %w", gvk.Kind, name, err)
			}
		} else {
			// Resource doesn't exist, create it
			_, err = resourceClient.Create(ctx, &obj, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create %s/%s: %w", gvk.Kind, name, err)
			}
		}
	}

	return nil
}

// pluralizeResource converts Kind to resource name (simple pluralization)
// For production use, consider using discovery client or a proper pluralization library
func pluralizeResource(kind string) string {
	// Simple pluralization rules
	switch kind {
	case "Endpoints":
		return "endpoints"
	case "NetworkPolicy":
		return "networkpolicies"
	case "Ingress":
		return "ingresses"
	default:
		// Simple rule: add 's' to lowercase kind
		return fmt.Sprintf("%ss", kind)
	}
}
