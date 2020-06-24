package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/common/constants"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type AuthFailure struct {
	httpCode int
	msg      string
}

func (e AuthFailure) Error() string {
	return fmt.Sprintf("authentication failed with http status code %v and msg: %v", e.httpCode, e.msg)
}

type notAuthorized struct{}

func (e notAuthorized) Error() string {
	return fmt.Sprintf("not authorized")
}

var NotAuthorized = notAuthorized{}

type NotAccessible struct {
	httpCode int
	msg      string
}

func (e NotAccessible) Error() string {
	return fmt.Sprintf("unable to create apiSession. http status code: %v, msg: %v", e.httpCode, e.msg)
}

type Client interface {
	Login(info map[string]interface{}, configTypes []string) (*edge.ApiSession, error)
	Refresh() (*time.Time, error)
	GetServices() ([]*edge.Service, error)
	CreateSession(svcId string, kind edge.SessionType) (*edge.Session, error)
	RefreshSession(id string) (*edge.Session, error)
}

func NewClient(ctrl *url.URL, tlsCfg *tls.Config) (Client, error) {
	return &ctrlClient{
		zitiUrl: ctrl,
		clt: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
			Timeout: 30 * time.Second,
		},
	}, nil
}

var authUrl, _ = url.Parse("/authenticate?method=cert")
var currSess, _ = url.Parse("/current-apiSession-apiSession")
var servicesUrl, _ = url.Parse("/services")
var sessionUrl, _ = url.Parse("/sessions")

type ctrlClient struct {
	zitiUrl    *url.URL
	clt        http.Client
	apiSession *edge.ApiSession
}

func (c *ctrlClient) CreateSession(svcId string, kind edge.SessionType) (*edge.Session, error) {
	body := fmt.Sprintf(`{"serviceId":"%s", "type": "%s"}`, svcId, kind)
	reqBody := bytes.NewBufferString(body)

	fullSessionUrl := c.zitiUrl.ResolveReference(sessionUrl).String()
	pfxlog.Logger().Debugf("requesting session from %v", fullSessionUrl)
	req, _ := http.NewRequest("POST", fullSessionUrl, reqBody)
	req.Header.Set(constants.ZitiSession, c.apiSession.Token)
	req.Header.Set("content-type", "application/json")

	logrus.WithField("service_id", svcId).Debug("requesting session")
	resp, err := c.clt.Do(req)

	if err != nil {
		return nil, err
	}

	return decodeSession(resp)
}

func (c *ctrlClient) RefreshSession(id string) (*edge.Session, error) {
	sessionLookupUrl, _ := url.Parse(fmt.Sprintf("/sessions/%v", id))
	sessionLookupUrlStr := c.zitiUrl.ResolveReference(sessionLookupUrl).String()
	pfxlog.Logger().Debugf("requesting session from %v", sessionLookupUrlStr)
	req, _ := http.NewRequest(http.MethodGet, sessionLookupUrlStr, nil)
	req.Header.Set(constants.ZitiSession, c.apiSession.Token)
	req.Header.Set("content-type", "application/json")

	logrus.WithField("sessionId", id).Debug("requesting session")
	resp, err := c.clt.Do(req)

	if err != nil {
		return nil, err
	}
	return decodeSession(resp)
}

func (c *ctrlClient) Login(info map[string]interface{}, configTypes []string) (*edge.ApiSession, error) {

	req := new(bytes.Buffer)
	reqMap := make(map[string]interface{})
	for k, v := range info {
		reqMap[k] = v
	}

	if len(configTypes) > 0 {
		reqMap["configTypes"] = configTypes
	}

	if err := json.NewEncoder(req).Encode(reqMap); err != nil {
		return nil, err
	}
	resp, err := c.clt.Post(c.zitiUrl.ResolveReference(authUrl).String(), "application/json", req)
	if err != nil {
		pfxlog.Logger().Errorf("failure to post auth %+v", err)
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(resp.Body)
		pfxlog.Logger().Errorf("failed to authenticate with Ziti controller, result status: %v, msg: %v", resp.StatusCode, string(msg))
		return nil, AuthFailure{
			httpCode: resp.StatusCode,
			msg:      string(msg),
		}
	}

	apiSessionResp := &edge.ApiSession{}

	_, err = edge.ApiResponseDecode(apiSessionResp, resp.Body)
	if err != nil {
		return nil, err
	}

	logrus.
		WithField("apiSession", apiSessionResp.Id).
		Debugf("logged in as %s/%s", apiSessionResp.Identity.Name, apiSessionResp.Identity.Id)

	c.apiSession = apiSessionResp
	return c.apiSession, nil

}

func (c *ctrlClient) Refresh() (*time.Time, error) {
	log := pfxlog.Logger()

	log.Debugf("refreshing apiSession apiSession")
	req, err := http.NewRequest("GET", c.zitiUrl.ResolveReference(currSess).String(), nil)
	req.Header.Set(constants.ZitiSession, c.apiSession.Token)
	resp, err := c.clt.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Errorf("failed to get current apiSession %+v, trying to login again", err)
		c.apiSession, err = c.Login(nil, nil)
		if err != nil {
			log.Fatalf("failed to login again")
			return nil, err
		}
	} else {
		apiSessionResp := &edge.ApiSession{}
		_, err = edge.ApiResponseDecode(apiSessionResp, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Fatalf("failed to parse current apiSession")
			return nil, err
		}
		c.apiSession = apiSessionResp
		log.Debugf("apiSession refreshed, new expiration[%s]", c.apiSession.Expires)
	}
	return &c.apiSession.Expires, nil
}

func (c *ctrlClient) GetServices() ([]*edge.Service, error) {
	servReq, _ := http.NewRequest("GET", c.zitiUrl.ResolveReference(servicesUrl).String(), nil)

	if c.apiSession.Token == "" {
		return nil, errors.New("apiSession apiSession token is empty")
	} else {
		pfxlog.Logger().Debugf("using apiSession apiSession token %v", c.apiSession.Token)
	}
	servReq.Header.Set(constants.ZitiSession, c.apiSession.Token)
	pgOffset := 0
	pgLimit := 100

	var services []*edge.Service
	for {
		q := servReq.URL.Query()
		q.Set("limit", strconv.Itoa(pgLimit))
		q.Set("offset", strconv.Itoa(pgOffset))
		servReq.URL.RawQuery = q.Encode()
		resp, err := c.clt.Do(servReq)

		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			if body, err := ioutil.ReadAll(resp.Body); err != nil {
				pfxlog.Logger().Debugf("error response: %v", body)
			}
			return nil, errors.New("unauthorized")
		}

		if err != nil {
			return nil, err
		}

		s := &[]*edge.Service{}
		meta, err := edge.ApiResponseDecode(s, resp.Body)

		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if meta == nil {
			// shouldn't happen
			return nil, errors.New("nil metadata in response to GET /services")
		}
		if meta.Pagination == nil {
			return nil, errors.New("nil pagination in response to GET /services")
		}

		if services == nil {
			services = make([]*edge.Service, 0, meta.Pagination.TotalCount)
		}

		for _, svc := range *s {
			services = append(services, svc)
		}

		pgOffset += pgLimit
		if pgOffset >= meta.Pagination.TotalCount {
			break
		}
	}

	return services, nil

}

func decodeSession(resp *http.Response) (*edge.Session, error) {
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, NotAuthorized
		}
		if resp.StatusCode == http.StatusBadRequest {
			return nil, NotAccessible{
				httpCode: resp.StatusCode,
				msg:      string(respBody),
			}
		}
		return nil, fmt.Errorf("failed to create session: %s\n%s", resp.Status, string(respBody))
	}

	session := new(edge.Session)
	_, err := edge.ApiResponseDecode(session, resp.Body)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to decode session response")
		return nil, err
	}
	return session, nil
}
