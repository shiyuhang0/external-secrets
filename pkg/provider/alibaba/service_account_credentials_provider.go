// /*
// Copyright Â© 2025 ESO Maintainer Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	providers "github.com/aliyun/credentials-go/credentials/providers"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// ServiceAccountCredentialsProvider refer to ali sdk OIDCCredentialsProviderBuilder.
// namespace, serviceAccount, audiences and k8sClient are added fields for k8s service account token request.
type ServiceAccountCredentialsProvider struct {
	oidcProviderARN string
	namespace       string
	serviceAccount  string
	k8sClient       corev1.CoreV1Interface
	audiences       []string
	roleArn         string
	roleSessionName string
	durationSeconds int
	policy          string
	// for sts endpoint
	stsRegionId string
	enableVpc   bool
	stsEndpoint string

	lastUpdateTimestamp int64
	expirationTimestamp int64
	sessionCredentials  *sessionCredentials
}

type ServiceAccountCredentialsProviderBuilder struct {
	provider *ServiceAccountCredentialsProvider
}

func NewServiceAccountCredentialsProviderBuilder() *ServiceAccountCredentialsProviderBuilder {
	return &ServiceAccountCredentialsProviderBuilder{
		provider: &ServiceAccountCredentialsProvider{},
	}
}

func (b *ServiceAccountCredentialsProviderBuilder) WithOIDCProviderARN(oidcProviderArn string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.oidcProviderARN = oidcProviderArn
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithRoleArn(roleArn string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.roleArn = roleArn
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithRoleSessionName(roleSessionName string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.roleSessionName = roleSessionName
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithDurationSeconds(durationSeconds int) *ServiceAccountCredentialsProviderBuilder {
	b.provider.durationSeconds = durationSeconds
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithStsRegionId(regionId string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.stsRegionId = regionId
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithEnableVpc(enableVpc bool) *ServiceAccountCredentialsProviderBuilder {
	b.provider.enableVpc = enableVpc
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithPolicy(policy string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.policy = policy
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithSTSEndpoint(stsEndpoint string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.stsEndpoint = stsEndpoint
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithServiceAccount(serviceAccount string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.serviceAccount = serviceAccount
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithNamespace(namespace string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.namespace = namespace
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) WithAudiences(audiences []string) *ServiceAccountCredentialsProviderBuilder {
	b.provider.audiences = audiences
	return b
}

func (b *ServiceAccountCredentialsProviderBuilder) Build() (provider *ServiceAccountCredentialsProvider, err error) {
	if b.provider.roleSessionName == "" {
		b.provider.roleSessionName = "credentials-go-" + strconv.FormatInt(time.Now().UnixNano()/1000, 10)
	}

	if b.provider.serviceAccount == "" {
		err = errors.New("the serviceAccount is empty")
		return provider, err
	}

	if b.provider.namespace == "" {
		err = errors.New("the namespace is empty")
		return provider, err
	}

	if len(b.provider.audiences) == 0 {
		b.provider.audiences = []string{"sts.aliyuncs.com"}
	}

	if b.provider.oidcProviderARN == "" {
		b.provider.oidcProviderARN = os.Getenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN")
	}

	if b.provider.oidcProviderARN == "" {
		err = errors.New("the OIDCProviderARN is empty")
		return provider, err
	}

	if b.provider.roleArn == "" {
		b.provider.roleArn = os.Getenv("ALIBABA_CLOUD_ROLE_ARN")
	}

	if b.provider.roleArn == "" {
		err = errors.New("the RoleArn is empty")
		return provider, err
	}

	if b.provider.durationSeconds == 0 {
		b.provider.durationSeconds = 3600
	}

	if b.provider.durationSeconds < 900 {
		err = errors.New("the Assume Role session duration should be in the range of 15min - max duration seconds")
		return provider, err
	}

	if b.provider.stsEndpoint == "" {
		if !b.provider.enableVpc {
			b.provider.enableVpc = strings.ToLower(os.Getenv("ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED")) == "true"
		}
		prefix := "sts"
		if b.provider.enableVpc {
			prefix = "sts-vpc"
		}
		if b.provider.stsRegionId != "" {
			b.provider.stsEndpoint = fmt.Sprintf("%s.%s.aliyuncs.com", prefix, b.provider.stsRegionId)
		} else if region := os.Getenv("ALIBABA_CLOUD_STS_REGION"); region != "" {
			b.provider.stsEndpoint = fmt.Sprintf("%s.%s.aliyuncs.com", prefix, region)
		} else {
			b.provider.stsEndpoint = "sts.aliyuncs.com"
		}
	}

	cfg, err := ctrlcfg.GetConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	b.provider.k8sClient = clientset.CoreV1()

	provider = b.provider
	return provider, err
}

type httpRequest struct {
	Method         string // http request method
	URL            string // http url
	Protocol       string // http or https
	Host           string // http host
	ReadTimeout    time.Duration
	ConnectTimeout time.Duration
	Proxy          string            // http proxy
	Form           map[string]string // http form
	Body           []byte            // request body for JSON or stream
	Path           string
	Queries        map[string]string
	Headers        map[string]string
}

type ossCredentials struct {
	SecurityToken   *string `json:"SecurityToken"`
	Expiration      *string `json:"Expiration"`
	AccessKeySecret *string `json:"AccessKeySecret"`
	AccessKeyId     *string `json:"AccessKeyId"`
}

type assumeRoleResponse struct {
	RequestID       *string          `json:"RequestId"`
	AssumedRoleUser *assumedRoleUser `json:"AssumedRoleUser"`
	Credentials     *ossCredentials  `json:"Credentials"`
}

type assumedRoleUser struct {
}

type sessionCredentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      string
}

func (provider *ServiceAccountCredentialsProvider) getIdentityToken() (_ []byte, err error) {
	log.V(1).Info("fetching token", "ns", provider.namespace, "sa", provider.serviceAccount)
	tokRsp, err := provider.k8sClient.ServiceAccounts(provider.namespace).CreateToken(context.Background(), provider.serviceAccount, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences: provider.audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("error creating service account token: %w", err)
	}
	return []byte(tokRsp.Status.Token), nil
}

func (provider *ServiceAccountCredentialsProvider) getCredentials() (session *sessionCredentials, err error) {
	req := &httpRequest{
		Method:   "POST",
		Protocol: "https",
		Host:     provider.stsEndpoint,
		Headers:  map[string]string{},
	}

	req.ConnectTimeout = 5 * time.Second
	req.ReadTimeout = 10 * time.Second

	queries := make(map[string]string)
	queries["Version"] = "2015-04-01"
	queries["Action"] = "AssumeRoleWithOIDC"
	queries["Format"] = "JSON"
	queries["Timestamp"] = getTimeInFormatISO8601()
	req.Queries = queries

	bodyForm := make(map[string]string)
	bodyForm["RoleArn"] = provider.roleArn
	bodyForm["OIDCProviderArn"] = provider.oidcProviderARN
	token, err := provider.getIdentityToken()
	if err != nil {
		return session, err
	}

	bodyForm["OIDCToken"] = string(token)
	if provider.policy != "" {
		bodyForm["Policy"] = provider.policy
	}

	bodyForm["RoleSessionName"] = provider.roleSessionName
	bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)
	req.Form = bodyForm

	// set headers
	req.Headers["Accept-Encoding"] = "identity"
	res, err := Do(req)
	if err != nil {
		return session, err
	}

	if res.StatusCode != http.StatusOK {
		message := "get session token failed: "
		err = errors.New(message + string(res.Body))
		return session, err
	}
	var data assumeRoleResponse
	err = json.Unmarshal(res.Body, &data)
	if err != nil {
		err = fmt.Errorf("get oidc sts token err, json.Unmarshal fail: %s", err.Error())
		return session, err
	}
	if data.Credentials == nil {
		err = fmt.Errorf("get oidc sts token err, fail to get credentials")
		return session, err
	}

	if data.Credentials.AccessKeyId == nil || data.Credentials.AccessKeySecret == nil || data.Credentials.SecurityToken == nil {
		err = fmt.Errorf("refresh RoleArn sts token err, fail to get credentials")
		return session, err
	}

	session = &sessionCredentials{
		AccessKeyId:     *data.Credentials.AccessKeyId,
		AccessKeySecret: *data.Credentials.AccessKeySecret,
		SecurityToken:   *data.Credentials.SecurityToken,
		Expiration:      *data.Credentials.Expiration,
	}
	return session, err
}

func (provider *ServiceAccountCredentialsProvider) needUpdateCredential() (result bool) {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *ServiceAccountCredentialsProvider) GetCredentials() (cc *providers.Credentials, err error) {
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {
		sessionCredentials, err1 := provider.getCredentials()
		if err1 != nil {
			return nil, err1
		}

		provider.sessionCredentials = sessionCredentials
		expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
		if err2 != nil {
			return nil, err2
		}

		provider.lastUpdateTimestamp = time.Now().Unix()
		provider.expirationTimestamp = expirationTime.Unix()
	}

	cc = &providers.Credentials{
		AccessKeyId:     provider.sessionCredentials.AccessKeyId,
		AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
		SecurityToken:   provider.sessionCredentials.SecurityToken,
		ProviderName:    provider.GetProviderName(),
	}
	return
}

func (provider *ServiceAccountCredentialsProvider) GetProviderName() string {
	return "service_account"
}

type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

var newRequest = http.NewRequest

func getURLFormedMap(source map[string]string) (urlEncoded string) {
	urlEncoder := url.Values{}
	for key, value := range source {
		urlEncoder.Add(key, value)
	}
	urlEncoded = urlEncoder.Encode()
	return
}

func getTimeInFormatISO8601() (timeStr string) {
	gmt := time.FixedZone("GMT", 0)

	return time.Now().In(gmt).Format("2006-01-02T15:04:05Z")
}

func Do(req *httpRequest) (res *Response, err error) {
	querystring := getURLFormedMap(req.Queries)
	// do request
	httpUrl := fmt.Sprintf("%s://%s%s?%s", req.Protocol, req.Host, req.Path, querystring)
	if req.URL != "" {
		httpUrl = req.URL
	}

	var body io.Reader
	if req.Method == "GET" {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(getURLFormedMap(req.Form))
	}

	httpRequest, err := newRequest(req.Method, httpUrl, body)
	if err != nil {
		return nil, err
	}

	if req.Form != nil {
		httpRequest.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	}

	for key, value := range req.Headers {
		if value != "" {
			httpRequest.Header.Set(key, value)
		}
	}

	httpClient := &http.Client{}

	if req.ReadTimeout != 0 {
		httpClient.Timeout = req.ReadTimeout + req.ConnectTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if req.Proxy != "" {
		var proxy *url.URL
		proxy, err = url.Parse(req.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	if req.ConnectTimeout != 0 {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   req.ConnectTimeout,
				DualStack: true,
			}).DialContext(ctx, network, address)
		}
	}

	httpClient.Transport = transport

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}

	defer httpResponse.Body.Close() //nolint:errcheck // skip error check

	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	res = &Response{
		StatusCode: httpResponse.StatusCode,
		Headers:    make(map[string]string),
		Body:       responseBody,
	}
	for key, v := range httpResponse.Header {
		res.Headers[key] = v[0]
	}

	return res, nil
}
