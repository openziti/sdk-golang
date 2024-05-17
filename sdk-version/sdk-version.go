package main

import (
	"fmt"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
)

func main() {
	_, sdkInfo := sdkinfo.GetSdkInfo()
	fmt.Printf("%s", sdkInfo.Version)
}
