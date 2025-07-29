package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     http.Header
		wantKey    string
		wantErr    bool
		errMessage string
	}{
		{
			name: "valid API key",
			header: http.Header{
				"Authorization": []string{"ApiKey 12345-abcdef"},
			},
			wantKey: "12345-abcdef",
			wantErr: false,
		},
		{
			name:       "missing Authorization header",
			header:     http.Header{},
			wantKey:    "",
			wantErr:    true,
			errMessage: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "malformed Authorization header (wrong prefix)",
			header: http.Header{
				"Authorization": []string{"Bearer 12345-abcdef"},
			},
			wantKey:    "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "malformed Authorization header (no key)",
			header: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:    "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.header)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if err.Error() != tc.errMessage {
					t.Errorf("Expected error %q, got %q", tc.errMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if gotKey != tc.wantKey {
					t.Errorf("Expected key %q, got %q", tc.wantKey, gotKey)
				}
			}
		})
	}
}
