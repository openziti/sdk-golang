package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	gohttp "net/http"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
)
var	svcName = "httpsdk"

type ZitiDoer struct {
	httpClient *gohttp.Client
}
type ZitiDialContext struct {
	context ziti.Context
	serviceName string
}
func (dc *ZitiDialContext) Dial(_ context.Context, _ string, _ string) (net.Conn, error) {
	return dc.context.Dial(dc.serviceName)
}
func NewZitiDoer(cfgFile string) *ZitiDoer {
	zitiCfg, err := config.NewFromFile(cfgFile)
	if err != nil {
		logrus.Errorf("failed to load ziti configuration file: %v", err)
	}
	ctx := ziti.NewContextWithConfig(zitiCfg)
	zitiDialContext := ZitiDialContext{context: ctx, serviceName: svcName}
	zitiTransport := gohttp.DefaultTransport.(*gohttp.Transport).Clone() // copy default transport
	zitiTransport.DialContext = zitiDialContext.Dial
	doer := &ZitiDoer{}
	doer.httpClient = &gohttp.Client{
		Transport: zitiTransport,
	}
	return doer
}
func(doer *ZitiDoer) Do(httpReq *gohttp.Request) (*gohttp.Response, error){
	return doer.httpClient.Do(httpReq)
}

func main() {
	userName := "admin"
	password := "admin"
	dbPtr := "test"
	identityFile := `influxdb-client-go-test.json`
	flag.Parse()

	//create a new "Doer" - in this case it is a simple struct which implements "Do"
	zitiDoer := NewZitiDoer(identityFile)

	token := fmt.Sprintf("%s:%s",userName, password)
	// Create a new client using an InfluxDB server base URL and an authentication token
	// For authentication token supply a string in the form: "username:password" as a token. Set empty value for an unauthenticated server
	opts := influxdb2.DefaultOptions()
	opts.HTTPOptions().SetHTTPDoer(zitiDoer)
	client := influxdb2.NewClientWithOptions("http://influx-no-ssl:8086", token, opts)

	// Get the blocking write client
	// Supply a string in the form database/retention-policy as a bucket. Skip retention policy for the default one, use just a database name (without the slash character)
	// Org name is not used
	bucket := dbPtr + "/autogen"
	writeAPI := client.WriteAPIBlocking("", bucket)
	// create point using full params constructor
	p := influxdb2.NewPoint("stat",
		map[string]string{"unit": "temperature"},
		map[string]interface{}{"avg": 24.5, "max": 45},
		time.Now())
	// Write data
	err := writeAPI.WritePoint(context.Background(), p)
	if err != nil {
		fmt.Printf("Write error: %s\n", err.Error())
	}

	// Get query client. Org name is not used
	queryAPI := client.QueryAPI("")
	// Supply string in a form database/retention-policy as a bucket. Skip retention policy for the default one, use just a database name (without the slash character)
	result, err := queryAPI.Query(context.Background(), `from(bucket:"`+ bucket +`")|> range(start: -1h) |> filter(fn: (r) => r._measurement == "stat")`)
	if err == nil {
		for result.Next() {
			if result.TableChanged() {
				fmt.Printf("table: %s\n", result.TableMetadata().String())
			}
			fmt.Printf("row: %s\n", result.Record().String())
		}
		if result.Err() != nil {
			fmt.Printf("Query error: %s\n", result.Err().Error())
		}
	} else {
		fmt.Printf("Query error: %s\n", err.Error())
	}

	// Close client
	client.Close()
}