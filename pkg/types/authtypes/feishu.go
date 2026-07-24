package authtypes

import (
	"encoding/json"

	"github.com/SigNoz/signoz/pkg/errors"
)

type FeishuConfig struct {
	// It is the application's ID (App ID) obtained from the Feishu open platform.
	ClientID string `json:"clientId"`

	// It is the application's secret (App Secret).
	ClientSecret string `json:"clientSecret"`

	// Whether to use the Lark (international) endpoints instead of the Feishu (China) endpoints. Defaults to "false"
	UseLark bool `json:"useLark"`
}

func (config *FeishuConfig) UnmarshalJSON(data []byte) error {
	type Alias FeishuConfig

	var temp Alias
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	if temp.ClientID == "" {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "clientId is required")
	}

	if temp.ClientSecret == "" {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "clientSecret is required")
	}

	*config = FeishuConfig(temp)
	return nil
}
