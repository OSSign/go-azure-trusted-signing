package goats_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	goats "github.com/ossign/go-azure-trusted-signing"
)

var fakeToken = &fake.TokenCredential{}

type MockHttpClient struct {
	MockResponse []*http.Response
	MockError    error

	ctr int
}

func (f *MockHttpClient) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Println("CTR is", f.ctr)
	fmt.Println("Responses length is", len(f.MockResponse))
	if f.ctr < len(f.MockResponse) {
		resp := f.MockResponse[f.ctr]
		f.ctr++
		return resp, f.MockError
	}
	f.ctr = 0
	return f.MockResponse[0], f.MockError
}

func GetMockHttpClient(response *http.Response, err error) *http.Client {
	return &http.Client{
		Transport: &MockHttpClient{
			MockResponse: []*http.Response{response},
			MockError:    err,
		},
	}
}

func GetMockHttpSeries(responses []*http.Response, err error) *http.Client {
	return &http.Client{
		Transport: &MockHttpClient{
			MockResponse: responses,
			MockError:    err,
		},
	}
}

func TestNewClient(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")
	c.SetHTTPClient(GetMockHttpClient(
		&http.Response{},
		nil,
	))
}
