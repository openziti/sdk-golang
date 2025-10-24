package edge_apis

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ApiSessionMarshalling(t *testing.T) {

	t.Run("test marshalling", func(t *testing.T) {
		req := require.New(t)
		type testStruct struct {
			ApiSession ApiSessionJsonWrapper `json:"apiSession"`
		}

		test := &testStruct{
			ApiSession: ApiSessionJsonWrapper{
				ApiSession: NewApiSessionOidc("access", "refresh"),
			},
		}

		testJson, err := json.Marshal(test)
		req.NoError(err)

		testUnmarhsal := &testStruct{}

		err = json.Unmarshal(testJson, testUnmarhsal)
		req.NoError(err)
		req.Equal(test.ApiSession.ApiSession.GetToken(), testUnmarhsal.ApiSession.ApiSession.GetToken())
	})
}
