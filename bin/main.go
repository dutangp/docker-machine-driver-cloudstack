package main

import (
	"github.com/dutangp/docker-machine-driver-tmcloudstack"
 "github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(cloudstack.NewDriver("", ""))
}
