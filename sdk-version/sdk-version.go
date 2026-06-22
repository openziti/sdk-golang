package main

import (
	"fmt"
	"github.com/openziti/sdk-golang/v2/ziti/sdkinfo"
)

func main() {
	_, sdkInfo := sdkinfo.GetSdkInfo()
	fmt.Printf("%s", sdkInfo.Version)
}
