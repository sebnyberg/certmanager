package certmanager

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_parseAzureSecretURL(t *testing.T) {
	type Resp struct {
		BaseURL       string
		SecretName    string
		SecretVersion string
	}

	for _, tc := range []struct {
		in      string
		want    Resp
		wantErr error
	}{
		{
			"https://test-vault.vault.azure.net/secrets/abc",
			Resp{"https://test-vault.vault.azure.net", "abc", ""}, nil,
		},
		{
			"https://test-vault.vault.azure.net/secrets/abc/1234",
			Resp{"https://test-vault.vault.azure.net", "abc", "1234"}, nil,
		},
		{
			"https://test-vault.vault.azure.net/secrets/",
			Resp{"", "", ""}, errInvalidKVSecretURL,
		},
	} {
		t.Run(tc.in, func(t *testing.T) {
			baseURL, secretName, version, gotErr := parseAzureSecretURL(tc.in)
			got := Resp{baseURL, secretName, version}

			if !cmp.Equal(tc.want, got) {
				t.Error("test failed", cmp.Diff(tc.want, got))
			}
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("wrong return err\nexpected: %v\ngot: %v", tc.wantErr, gotErr)
			}
		})
	}
}
