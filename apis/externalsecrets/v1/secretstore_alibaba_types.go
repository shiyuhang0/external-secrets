/*
Copyright © 2025 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// AlibabaAuth contains a secretRef for credentials.
type AlibabaAuth struct {
	// +optional
	SecretRef *AlibabaAuthSecretRef `json:"secretRef,omitempty"`
	// +optional
	RRSAAuth *AlibabaRRSAAuth `json:"rrsa,omitempty"`
	// +optional
	ServiceAccountAuth *AlibabaServiceAccountAuth `json:"serviceAccount,omitempty"`
}

// AlibabaAuthSecretRef holds secret references for Alibaba credentials.
type AlibabaAuthSecretRef struct {
	// The AccessKeyID is used for authentication
	AccessKeyID esmeta.SecretKeySelector `json:"accessKeyIDSecretRef"`
	// The AccessKeySecret is used for authentication
	AccessKeySecret esmeta.SecretKeySelector `json:"accessKeySecretSecretRef"`
}

// Authenticate against Alibaba using RRSA.
type AlibabaRRSAAuth struct {
	OIDCProviderARN   string `json:"oidcProviderArn"`
	OIDCTokenFilePath string `json:"oidcTokenFilePath"`
	RoleARN           string `json:"roleArn"`
	SessionName       string `json:"sessionName"`
}

// Authenticate against Alibaba using service account tokens.
type AlibabaServiceAccountAuth struct {
	// The name of the ServiceAccount resource being referred to.
	// +kubebuilder:validation:MinLength:=1
	// +kubebuilder:validation:MaxLength:=253
	// +kubebuilder:validation:Pattern:=^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
	Name string `json:"name"`

	// Namespace of the resource being referred to.
	// Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.
	// +optional
	// +kubebuilder:validation:MinLength:=1
	// +kubebuilder:validation:MaxLength:=63
	// +kubebuilder:validation:Pattern:=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	Namespace *string `json:"namespace,omitempty"`

	// Audience specifies the `aud` claim for the service account token
	// defaults to `sts.aliyuncs.com` if not specified.
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// The OIDCProviderARN is used for authentication
	// if not specified the controller will use the value of the
	// ALIBABA_CLOUD_OIDC_PROVIDER_ARN environment variable of the controller pod.
	// +optional
	OIDCProviderARN string `json:"oidcProviderArn"`

	// The RoleARN is used for authentication
	// if not specified the controller will use the value of the
	// ALIBABA_CLOUD_ROLE_ARN environment variable of the controller pod.
	// +optional
	RoleARN string `json:"roleArn"`
}

// AlibabaProvider configures a store to sync secrets using the Alibaba Secret Manager provider.
type AlibabaProvider struct {
	Auth AlibabaAuth `json:"auth"`
	// Alibaba Region to be used for the provider
	RegionID string `json:"regionID"`
}
