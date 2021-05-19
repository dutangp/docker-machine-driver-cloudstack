package cloudstack

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	"github.com/dutangp/go-cloudstack/cloudstack"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	driverName   = "cloudstack"
	dockerPort   = 2376
	swarmPort    = 3376
	diskDatadisk = "DATADISK"
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("cloudstack driver requires the --cloudstack-%s option", e.option)
}

// Driver is the new cloudstack driver
type Driver struct {
	*drivers.BaseDriver
	ID                   string
	APIURL               string
	APIKey               string
	SecretKey            string
	IBuser               string
	IBpassword           string
	HTTPGETOnly          bool
	JobTimeOut           int64
	UsePrivateIP         bool
	UsePortForward       bool
	PublicIP             string
	PublicIPID           string
	DisassociatePublicIP bool
	MacAddress           string
	SSHKeyPair           string
	SSHPrivateKeyBase64  string
	SSHKeyPath           string
	SSHManage            bool
	PrivateIP            string
	CIDRList             []string
	FirewallRuleIds      []string
	Expunge              bool
	Template             string
	TemplateID           string
	ServiceOffering      string
	ServiceOfferingID    string
	DeleteVolumes        bool
	DiskOffering         string
	DiskOfferingID       string
	DiskSize             int
	DiskRootSize         int
	Network              string
	NetworkID            string
	NetworkCidr          string
	Zone                 string
	ZoneID               string
	NetworkType          string
	UserDataFile         string
	UserData             string
	Project              string
	ProjectID            string
	TMTags               string
	Tags                 []string
	DomainName           string
	DisplayName          string
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "cloudstack-api-url",
			Usage:  "CloudStack API URL",
			EnvVar: "CLOUDSTACK_API_URL",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-api-key",
			Usage:  "CloudStack API key",
			EnvVar: "CLOUDSTACK_API_KEY",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-secret-key",
			Usage:  "CloudStack API secret key",
			EnvVar: "CLOUDSTACK_SECRET_KEY",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-infoblox-user",
			Usage:  "CloudStack Infoblox user",
			EnvVar: "CLOUDSTACK_INFOBLOX_USER",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-infoblox-password",
			Usage:  "CloudStack Infoblox password",
			EnvVar: "CLOUDSTACK_INFOBLOX_PASSWORD",
		},
		mcnflag.BoolFlag{
			Name:   "cloudstack-http-get-only",
			Usage:  "Only use HTTP GET to execute CloudStack API",
			EnvVar: "CLOUDSTACK_HTTP_GET_ONLY",
		},
		mcnflag.IntFlag{
			Name:   "cloudstack-timeout",
			Usage:  "time(seconds) allowed to complete async job",
			EnvVar: "CLOUDSTACK_TIMEOUT",
			Value:  300,
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-use-private-address",
			Usage: "Use a private IP to access the machine",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-use-port-forward",
			Usage: "Use port forwarding rule to access the machine",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-public-ip",
			Usage: "CloudStack Public IP",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-ssh-user",
			Usage: "CloudStack SSH user",
			Value: "root",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-ssh-privatekey-base64",
			Usage: "CloudStack SSH privateKey base64",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-ssh-manage",
			Usage: "CloudStack SSH Management",
		},
		mcnflag.StringSliceFlag{
			Name:  "cloudstack-cidr",
			Usage: "Source CIDR to give access to the machine. default 0.0.0.0/0",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-expunge",
			Usage: "Whether or not to expunge the machine upon removal",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-template",
			Usage: "CloudStack template",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-template-id",
			Usage: "Cloudstack template id",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-service-offering",
			Usage: "CloudStack service offering",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-service-offering-id",
			Usage: "CloudStack service offering id",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-network",
			Usage: "CloudStack network",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-network-id",
			Usage: "CloudStack network id",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-zone",
			Usage: "CloudStack zone",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-zone-id",
			Usage: "CloudStack zone id",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-userdata-file",
			Usage: "CloudStack Userdata file",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-userdata-base64",
			Usage: "CloudStack Userdata Base64",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-project",
			Usage: "CloudStack project",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-project-id",
			Usage: "CloudStack project id",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-tm-tag",
			Usage: "key:value TM tags to be created",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-disk-offering",
			Usage: "Cloudstack disk offering",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-disk-offering-id",
			Usage: "Cloudstack disk offering id",
		},
		mcnflag.IntFlag{
			Name:  "cloudstack-disk-size",
			Usage: "Disk offering custom size",
		},
		mcnflag.IntFlag{
			Name:  "cloudstack-root-disk-size",
			Usage: "Disk Root size",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-delete-volumes",
			Usage: "Whether or not to delete data volumes associated with the machine upon removal",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-displayname",
			Usage: "Cloudstack virtual machine displayname",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-domainname",
			Usage: "Cloudstack virtual machine domainname",
		},
	}
}

// NewDriver creates new driver instance
func NewDriver(hostName, storePath string) drivers.Driver {
	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
		FirewallRuleIds: []string{},
	}
	return driver
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) GetMachineName() string {
	if d.DisplayName == "" {
		return d.MachineName
	} else {
		return d.DisplayName
	}
}

// GetSSHHostname sets hostname to the host ip
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHUsername gets the ssh user
func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "root"
	}
	return d.SSHUser
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.APIURL = flags.String("cloudstack-api-url")
	d.APIKey = flags.String("cloudstack-api-key")
	d.SecretKey = flags.String("cloudstack-secret-key")
	d.IBuser = flags.String("cloudstack-infoblox-user")
	d.IBpassword = flags.String("cloudstack-infoblox-password")
	d.UsePrivateIP = flags.Bool("cloudstack-use-private-address")
	d.UsePortForward = flags.Bool("cloudstack-use-port-forward")
	d.HTTPGETOnly = flags.Bool("cloudstack-http-get-only")
	d.JobTimeOut = int64(flags.Int("cloudstack-timeout"))
	d.SSHUser = flags.String("cloudstack-ssh-user")
	d.SSHManage = flags.Bool("cloudstack-ssh-manage")
	d.SSHPrivateKeyBase64 = flags.String("cloudstack-ssh-privatekey-base64")
	d.CIDRList = flags.StringSlice("cloudstack-cidr")
	d.Expunge = flags.Bool("cloudstack-expunge")
	d.TMTags = flags.String("cloudstack-tm-tag")
	d.DeleteVolumes = flags.Bool("cloudstack-delete-volumes")
	d.DiskSize = flags.Int("cloudstack-disk-size")
	d.DiskRootSize = flags.Int("cloudstack-root-disk-size")
	d.DisplayName = flags.String("cloudstack-displayname")
	d.DomainName = flags.String("cloudstack-domainname")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	if err := d.setProject(flags.String("cloudstack-project"), flags.String("cloudstack-project-id")); err != nil {
		return err
	}
	if err := d.setZone(flags.String("cloudstack-zone"), flags.String("cloudstack-zone-id")); err != nil {
		return err
	}
	if err := d.setTemplate(flags.String("cloudstack-template"), flags.String("cloudstack-template-id")); err != nil {
		return err
	}
	if err := d.setServiceOffering(flags.String("cloudstack-service-offering"), flags.String("cloudstack-service-offering-id")); err != nil {
		return err
	}
	if err := d.setNetwork(flags.String("cloudstack-network"), flags.String("cloudstack-network-id")); err != nil {
		return err
	}
	if err := d.setPublicIP(flags.String("cloudstack-public-ip")); err != nil {
		return err
	}
	if err := d.setUserData(flags.String("cloudstack-userdata-file"), flags.String("cloudstack-userdata-base64")); err != nil {
		return err
	}
	if err := d.setDiskOffering(flags.String("cloudstack-disk-offering"), flags.String("cloudstack-disk-offering-id")); err != nil {
		return err
	}
	if d.DomainName == "" {
		return &configError{option: "domainname"}
	}
	if d.DisplayName == "" {
		d.DisplayName = d.MachineName + "." + d.DomainName
	}
	d.SSHKeyPair = d.DisplayName
	if d.APIURL == "" {
		return &configError{option: "api-url"}
	}
	if d.APIKey == "" {
		return &configError{option: "api-key"}
	}
	if d.SecretKey == "" {
		return &configError{option: "secret-key"}
	}
	if d.IBuser == "" {
		return &configError{option: "infoblox-user"}
	}
	if d.IBpassword == "" {
		return &configError{option: "infoblox-password"}
	}
	if d.Template == "" {
		return &configError{option: "template"}
	}
	if d.ServiceOffering == "" {
		return &configError{option: "service-offering"}
	}
	if d.Zone == "" {
		return &configError{option: "zone"}
	}
	if len(d.CIDRList) == 0 {
		d.CIDRList = []string{"0.0.0.0/0"}
	}
	d.DisassociatePublicIP = false
	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

// GetIP returns the IP that this host is available at
func (d *Driver) GetIP() (string, error) {
	if d.UsePrivateIP {
		return d.PrivateIP, nil
	}
	return d.PublicIP, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	cs := d.getClient()
	vm, count, err := cs.VirtualMachine.GetVirtualMachineByID(d.ID, d.setParams)
	if err != nil {
		return state.Error, err
	}

	if count == 0 {
		return state.None, fmt.Errorf("machine does not exist, use create command to create it")
	}

	switch vm.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}

	return state.None, nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	if !d.SSHManage {
		if err := d.checkKeyPair(); err != nil {
			return err
		}
	}

	if err := d.checkInstance(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GoSleep(sec int) {
	rand.Seed(time.Now().UnixNano())
	n := time.Duration(rand.Intn(sec)) * time.Second // n will be between 0 and 10
	log.Debugf("sleep for %s seconds", n)
	time.Sleep(n)
}

func (d *Driver) PostInfoblox(url string, data []byte) error {
	log.Debugf("PostInfoblox: %s", url)
	log.Debugf("Json send %s\n", data)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Infof("Error reading request. ", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(d.IBuser, d.IBpassword)

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 30, Transport: tr}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("%s", err)
		log.Warnf("Error reading response. ", err)
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Infof("Error reading body. ", err)
	}

	log.Debugf("%s\n", body)

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	cs := d.getClient()
	if !d.SSHManage {
		if err := d.createKeyPair(); err != nil {
			return err
		}
	}
	p := cs.VirtualMachine.NewDeployVirtualMachineParams(
		d.ServiceOfferingID, d.TemplateID, d.ZoneID)
	p.SetName(strings.Replace(d.DisplayName, ".", "-", -1))
	p.SetDisplayname(d.DisplayName)
	p.SetHostname(d.DisplayName)
	d.Tags = strings.Fields(d.TMTags)
	if !d.SSHManage {
		log.Infof("Setting Keypair for VM: %s", d.SSHKeyPair)
		p.SetKeypair(d.SSHKeyPair)
	}
	if d.UserData != "" {
		p.SetUserdata(d.UserData)
	}
	if d.NetworkID != "" {
		p.SetNetworkids([]string{d.NetworkID})
	}
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	if d.DiskOfferingID != "" {
		p.SetDiskofferingid(d.DiskOfferingID)
		if d.DiskSize != 0 {
			p.SetSize(int64(d.DiskSize))
		}
	}
	if d.DiskRootSize != 0 {
		p.SetRootdisksize(int64(d.DiskRootSize))
	}
	if d.NetworkType == "Basic" {
		if err := d.createSecurityGroup(); err != nil {
			return err
		}
		p.SetSecuritygroupnames([]string{d.MachineName})
	}
	p.SetStartvm(false)

	log.Info("Creating CloudStack instance...")
	vm, err := cs.VirtualMachine.DeployVirtualMachine(p)
	if err != nil {
		return err
	}

	d.ID = vm.Id
	d.PrivateIP = d.DisplayName
	d.MacAddress = vm.Nic[0].Macaddress

	// Add IP to Infoblox
	log.Info("Checking if DNS already exists...")

	url := "https://dns.cloudsys.tmcs/wapi/v2.7.3/record:host?_return_fields%2B=name,ipv4addrs&_return_as_object=1"
	data := []byte(`{
		"name":"` + d.DisplayName + `",
		"ipv4addrs":[{
			"ipv4addr":"func:nextavailableip:` + d.NetworkCidr + `,default",
			"mac":"` + d.MacAddress + `"
		}]
	}`)

	call := 1
	for call <= 10 {
		log.Debugf("Check IP in Infoblox %s", d.DisplayName)
		r := net.Resolver{PreferGo: true}
		ctx := context.Background()
		ips, err := r.LookupIPAddr(ctx, d.DisplayName)

		if err != nil {
			log.Debugf("err: %s", err)
			log.Debugf("IP not found...")
			log.Info("Add the Machine in DNS...")
			d.PostInfoblox(url, data)
			d.GoSleep(5)
		} else {
			log.Debugf("IP found %s", ips)
			break
		}

		call++
	}

	if call > 10 {
		return fmt.Errorf("too many call to InfoBlox.")
	}

	// Restart Infoblox
	url = "https://dns.cloudsys.tmcs/wapi/v2.7.3/grid/b25lLmNsdXN0ZXIkMA:syseng?_function=restartservices"
	data = []byte(`{"restart_option" : "RESTART_IF_NEEDED", "member_order" : "SIMULTANEOUSLY", "service_option" : "ALL"}`)

	call = 1
	for call <= 5 {
		d.GoSleep(2)
		log.Info("Restarting Infoblox Services...")
		if err := d.PostInfoblox(url, data); err == nil {
			break
		}
		call++
	}

	if call > 10 {
		return fmt.Errorf("too many call to DNS")
	}

	d.GoSleep(5)

	/*
		if d.NetworkType == "Basic" {
			d.PublicIP = d.PrivateIP
		}
		if d.NetworkType == "Advanced" && !d.UsePrivateIP {
			if d.PublicIPID == "" {
				if err := d.associatePublicIP(); err != nil {
					return err
				}
			}
			if err := d.configureFirewallRules(); err != nil {
				return err
			}
			if d.UsePortForward {
				if err := d.configurePortForwardingRules(); err != nil {
					return err
				}
			} else {
				if err := d.enableStaticNat(); err != nil {
					return err
				}
			}
		}
	*/
	if len(d.Tags) > 0 {
		if err := d.createTags(); err != nil {
			return err
		}
	}

	d.IPAddress = d.PrivateIP
	d.SSHPort, err = d.GetSSHPort()

	if d.SSHManage {
		if err := d.tmcopySSHKey(); err != nil {
			return err
		}
	}

	log.Info("Starting CloudStack instance...")
	if err := d.Start(); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	cs := d.getClient()
	p := cs.VirtualMachine.NewDestroyVirtualMachineParams(d.ID)
	p.SetExpunge(d.Expunge)
	// if err := d.deleteFirewallRules(); err != nil {
	// 	return err
	// }
	// if err := d.disassociatePublicIP(); err != nil {
	// 	return err
	// }
	if !d.SSHManage {
		log.Info("Removing SSH Keypair...")
		if err := d.deleteKeyPair(); err != nil {
			return err
		}
	}
	log.Info("Removing CloudStack instance...")
	if _, err := cs.VirtualMachine.DestroyVirtualMachine(p); err != nil {
		return err
	}
	if d.NetworkType == "Basic" {
		if err := d.deleteSecurityGroup(); err != nil {
			return err
		}
	}
	if d.DeleteVolumes {
		if err := d.deleteVolumes(); err != nil {
			return err
		}
	}
	return nil
}

// Start a host
func (d *Driver) Start() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Running {
		log.Info("Machine is already running")
		return nil
	}

	if vmstate == state.Starting {
		log.Info("Machine is already starting")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStartVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.StartVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		log.Info("Machine is already stopped")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStopVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.StopVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Restart a host.
func (d *Driver) Restart() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		return fmt.Errorf("machine is stopped, use start command to start it")
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewRebootVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.RebootVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) getClient() *cloudstack.CloudStackClient {
	cs := cloudstack.NewAsyncClient(d.APIURL, d.APIKey, d.SecretKey, false)
	cs.HTTPGETOnly = d.HTTPGETOnly
	cs.AsyncTimeout(d.JobTimeOut)
	return cs
}

func (d *Driver) setZone(zone string, zoneID string) error {
	d.Zone = zone
	d.ZoneID = zoneID
	d.NetworkType = ""

	if d.Zone == "" && d.ZoneID == "" {
		return nil
	}

	cs := d.getClient()

	var z *cloudstack.Zone
	var err error
	if d.ZoneID != "" {
		z, _, err = cs.Zone.GetZoneByID(d.ZoneID, d.setParams)
	} else {
		z, _, err = cs.Zone.GetZoneByName(d.Zone, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("unable to get zone: %v", err)
	}

	d.Zone = z.Name
	d.ZoneID = z.Id
	d.NetworkType = z.Networktype

	log.Debugf("zone: %q", d.Zone)
	log.Debugf("zone id: %q", d.ZoneID)
	log.Debugf("network type: %q", d.NetworkType)

	return nil
}

func (d *Driver) setTemplate(templateName string, templateID string) error {
	d.Template = templateName
	d.TemplateID = templateID

	if d.Template == "" && d.TemplateID == "" {
		return nil
	}

	if d.ZoneID == "" {
		return fmt.Errorf("unable to get template: zone is not set")
	}

	cs := d.getClient()
	var template *cloudstack.Template
	var err error
	if d.TemplateID != "" {
		template, _, err = cs.Template.GetTemplateByID(d.TemplateID, "executable", d.setParams)
	} else {
		template, _, err = cs.Template.GetTemplateByName(d.Template, "executable", d.ZoneID, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("unable to get template: %v", err)
	}

	d.TemplateID = template.Id
	d.Template = template.Name

	log.Debugf("template id: %q", d.TemplateID)
	log.Debugf("template name: %q", d.Template)

	return nil
}

func (d *Driver) setServiceOffering(serviceoffering string, serviceofferingID string) error {
	d.ServiceOffering = serviceoffering
	d.ServiceOfferingID = serviceofferingID

	if d.ServiceOffering == "" && d.ServiceOfferingID == "" {
		return nil
	}

	cs := d.getClient()
	var service *cloudstack.ServiceOffering
	var err error
	if d.ServiceOfferingID != "" {
		service, _, err = cs.ServiceOffering.GetServiceOfferingByID(d.ServiceOfferingID, d.setParams)
	} else {
		service, _, err = cs.ServiceOffering.GetServiceOfferingByName(d.ServiceOffering, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("unable to get service offering: %v", err)
	}

	d.ServiceOfferingID = service.Id
	d.ServiceOffering = service.Name

	log.Debugf("service offering id: %q", d.ServiceOfferingID)
	log.Debugf("service offering name: %q", d.ServiceOffering)

	return nil
}

func (d *Driver) setDiskOffering(diskOffering string, diskOfferingID string) error {
	d.DiskOffering = diskOffering
	d.DiskOfferingID = diskOfferingID

	if d.DiskOffering == "" && d.DiskOfferingID == "" {
		return nil
	}

	cs := d.getClient()
	var disk *cloudstack.DiskOffering
	var err error
	if d.DiskOfferingID != "" {
		disk, _, err = cs.DiskOffering.GetDiskOfferingByID(d.DiskOfferingID, d.setParams)
	} else {
		disk, _, err = cs.DiskOffering.GetDiskOfferingByName(d.DiskOffering, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("unable to get disk offering: %v", err)
	}

	d.DiskOfferingID = disk.Id
	d.DiskOffering = disk.Name

	log.Debugf("disk offering id: %q", d.DiskOfferingID)
	log.Debugf("disk offering name: %q", d.DiskOffering)

	return nil
}

func (d *Driver) setNetwork(networkName string, networkID string) error {
	d.Network = networkName
	d.NetworkID = networkID

	if d.Network == "" && d.NetworkID == "" {
		return nil
	}

	cs := d.getClient()
	var network *cloudstack.Network
	var err error
	if d.NetworkID != "" {
		network, _, err = cs.Network.GetNetworkByID(d.NetworkID, d.setParams)
	} else {
		network, _, err = cs.Network.GetNetworkByName(d.Network, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("unable to get network: %v", err)
	}

	d.NetworkID = network.Id
	d.Network = network.Name
	d.NetworkCidr = network.Cidr

	log.Debugf("network id: %q", d.NetworkID)
	log.Debugf("network name: %q", d.Network)
	log.Debugf("network cidr: %q", d.NetworkCidr)

	return nil
}

func (d *Driver) setPublicIP(publicip string) error {
	d.PublicIP = publicip
	d.PublicIPID = ""

	if d.PublicIP == "" {
		return nil
	}

	cs := d.getClient()
	p := cs.Address.NewListPublicIpAddressesParams()
	p.SetIpaddress(d.PublicIP)
	ips, err := cs.Address.ListPublicIpAddresses(p)
	if err != nil {
		return fmt.Errorf("unable to get public ip id: %s", err)
	}
	if ips.Count < 1 {
		return fmt.Errorf("unable to get public ip id: Not Found %s", d.PublicIP)
	}

	d.PublicIPID = ips.PublicIpAddresses[0].Id

	log.Debugf("public ip id: %q", d.PublicIPID)

	return nil
}

func (d *Driver) setUserData(userDataFile string, userDataBase64 string) error {
	d.UserDataFile = userDataFile
	d.UserData = userDataBase64

	if d.UserDataFile == "" {
		return nil
	}

	data, err := ioutil.ReadFile(d.UserDataFile)
	if err != nil {
		return fmt.Errorf("Failed to read user data file: %s", err)
	}

	d.UserData = base64.StdEncoding.EncodeToString(data)

	return nil
}

func (d *Driver) readUserDataFromURL(userDataURL string) ([]byte, error) {
	c := &http.Client{}

	resp, err := c.Get(userDataURL)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)

}

func (d *Driver) setProject(projectName string, projectID string) error {
	d.Project = projectName
	d.ProjectID = projectID

	if d.Project == "" && d.ProjectID == "" {
		return nil
	}

	cs := d.getClient()
	var p *cloudstack.Project
	var err error
	if d.ProjectID != "" {
		p, _, err = cs.Project.GetProjectByID(d.ProjectID)
	} else {
		p, _, err = cs.Project.GetProjectByName(d.Project)
	}
	if err != nil {
		return fmt.Errorf("invalid project: %s", err)
	}

	d.ProjectID = p.Id
	d.Project = p.Name

	log.Debugf("project id: %s", d.ProjectID)
	log.Debugf("project name: %s", d.Project)

	return nil
}

func (d *Driver) checkKeyPair() error {
	cs := d.getClient()

	log.Infof("Checking if SSH key pair (%v) already exists...", d.SSHKeyPair)

	p := cs.SSH.NewListSSHKeyPairsParams()
	p.SetName(d.SSHKeyPair)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	res, err := cs.SSH.ListSSHKeyPairs(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {
		return fmt.Errorf("ssh key pair (%v) already exists", d.SSHKeyPair)
	}
	return nil
}

func (d *Driver) getPubKeyFingerprint(pub string) (string, error) {

	parts := strings.Fields(string(pub))
	if len(parts) < 2 {
		return "", errors.New("Bad pub key")
	}

	k, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	fp := md5.Sum([]byte(k))

	var fSum []string

	fmt.Print("MD5:")
	for i, b := range fp {

		fSum = append(fSum, fmt.Sprintf("%02x", b))
		if i < len(fp)-1 {
			fSum = append(fSum, ":")
		}
	}

	return strings.Join(fSum, ""), nil

}

func (d *Driver) checkKeyPairByFingerprint(pubKey string) (bool, error) {
	cs := d.getClient()

	fp, err := d.getPubKeyFingerprint(pubKey)

	if err != nil {
		return false, err
	}

	log.Infof("Checking for matching public key fingerprints...", d.SSHKeyPair)
	p := cs.SSH.NewListSSHKeyPairsParams()
	p.SetFingerprint(fp)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	res, err := cs.SSH.ListSSHKeyPairs(p)
	if err != nil {
		return false, err
	}
	if res.Count > 0 {
		for _, c := range res.SSHKeyPairs {
			if c.Fingerprint == fp {
				log.Infof("Found matching fingerprint, using key pair: %s", c.Name)
				d.SSHKeyPair = c.Name
				return true, nil
			}
		}
	}

	return false, nil
}

func (d *Driver) checkInstance() error {
	cs := d.getClient()

	log.Infof("Checking if instance (%v) already exists...", d.MachineName)

	p := cs.VirtualMachine.NewListVirtualMachinesParams()
	p.SetName(d.DisplayName)
	p.SetZoneid(d.ZoneID)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	res, err := cs.VirtualMachine.ListVirtualMachines(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {
		return fmt.Errorf("instance (%v) already exists", d.SSHKeyPair)
	}
	return nil
}

func (d *Driver) tmcopySSHKey() error {
	var destinationFile string
	destinationFile = "/management-state/node/nodes/" + d.MachineName + "/machines/" + d.MachineName + "/id_rsa"

	data, err := base64.StdEncoding.DecodeString(d.SSHPrivateKeyBase64)
	if err != nil {
		return err
	}

	log.Infof("Copy SSH key...")

	err = ioutil.WriteFile(destinationFile, data, 0600)
	if err != nil {
		return fmt.Errorf("Error creating file", err)
	}

	return nil
}

func (d *Driver) createKeyPair() error {
	cs := d.getClient()

	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	log.Infof("Registering SSH key pair...")

	p := cs.SSH.NewRegisterSSHKeyPairParams(d.SSHKeyPair, string(publicKey))
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	if _, err := cs.SSH.RegisterSSHKeyPair(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) deleteKeyPair() error {
	cs := d.getClient()

	log.Infof("Deleting SSH key pair...")

	p := cs.SSH.NewDeleteSSHKeyPairParams(d.SSHKeyPair)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}

	if _, err := cs.SSH.DeleteSSHKeyPair(p); err != nil {
		// Throw away the error because it most likely means that a key doesn't exist
		// It is ok because we can use the same key for multiple machines.
		log.Warnf("Key may not exist: %s", err)
		return nil
	}

	return nil
}

func (d *Driver) deleteVolumes() error {
	cs := d.getClient()

	log.Info("Deleting volumes...")

	p := cs.Volume.NewListVolumesParams()
	p.SetVirtualmachineid(d.ID)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	volResponse, err := cs.Volume.ListVolumes(p)
	if err != nil {
		return err
	}
	for _, v := range volResponse.Volumes {
		if v.Type != diskDatadisk {
			continue
		}
		p := cs.Volume.NewDetachVolumeParams()
		p.SetId(v.Id)
		_, err := cs.Volume.DetachVolume(p)
		if err != nil {
			return err
		}
		_, err = cs.Volume.DeleteVolume(cs.Volume.NewDeleteVolumeParams(v.Id))
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) associatePublicIP() error {
	cs := d.getClient()
	log.Infof("Associating public ip address...")
	p := cs.Address.NewAssociateIpAddressParams()
	p.SetZoneid(d.ZoneID)
	if d.NetworkID != "" {
		p.SetNetworkid(d.NetworkID)
	}
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	ip, err := cs.Address.AssociateIpAddress(p)
	if err != nil {
		return err
	}
	d.PublicIP = ip.Ipaddress
	d.PublicIPID = ip.Id
	d.DisassociatePublicIP = true

	return nil
}

func (d *Driver) disassociatePublicIP() error {
	if !d.DisassociatePublicIP {
		return nil
	}

	cs := d.getClient()
	log.Infof("Disassociating public ip address...")
	p := cs.Address.NewDisassociateIpAddressParams(d.PublicIPID)
	if _, err := cs.Address.DisassociateIpAddress(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) enableStaticNat() error {
	cs := d.getClient()
	log.Infof("Enabling Static Nat...")
	p := cs.NAT.NewEnableStaticNatParams(d.PublicIPID, d.ID)
	if _, err := cs.NAT.EnableStaticNat(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureFirewallRule(publicPort, privatePort int) error {
	cs := d.getClient()

	log.Debugf("Creating firewall rule ... : cidr list: %v, port %d", d.CIDRList, publicPort)
	p := cs.Firewall.NewCreateFirewallRuleParams(d.PublicIPID, "tcp")
	p.SetCidrlist(d.CIDRList)
	p.SetStartport(publicPort)
	p.SetEndport(publicPort)
	rule, err := cs.Firewall.CreateFirewallRule(p)
	if err != nil {
		// If the error reports the port is already open, just ignore.
		if !strings.Contains(err.Error(), fmt.Sprintf(
			"The range specified, %d-%d, conflicts with rule", publicPort, publicPort)) {
			return err
		}
	} else {
		d.FirewallRuleIds = append(d.FirewallRuleIds, rule.Id)
	}

	return nil
}

func (d *Driver) configurePortForwardingRule(publicPort, privatePort int) error {
	cs := d.getClient()

	log.Debugf("Creating port forwarding rule ... : cidr list: %v, port %d", d.CIDRList, publicPort)
	p := cs.Firewall.NewCreatePortForwardingRuleParams(
		d.PublicIPID, privatePort, "tcp", publicPort, d.ID)
	p.SetOpenfirewall(false)
	if _, err := cs.Firewall.CreatePortForwardingRule(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureFirewallRules() error {
	log.Info("Creating firewall rule for ssh port ...")

	if err := d.configureFirewallRule(22, 22); err != nil {
		return err
	}

	log.Info("Creating firewall rule for docker port ...")
	if err := d.configureFirewallRule(dockerPort, dockerPort); err != nil {
		return err
	}

	if d.SwarmMaster {
		log.Info("Creating firewall rule for swarm port ...")
		if err := d.configureFirewallRule(swarmPort, swarmPort); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) deleteFirewallRules() error {
	if len(d.FirewallRuleIds) > 0 {
		log.Info("Removing firewall rules...")
		for _, id := range d.FirewallRuleIds {
			cs := d.getClient()
			f := cs.Firewall.NewDeleteFirewallRuleParams(id)
			if _, err := cs.Firewall.DeleteFirewallRule(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Driver) configurePortForwardingRules() error {
	log.Info("Creating port forwarding rule for ssh port ...")

	if err := d.configurePortForwardingRule(22, 22); err != nil {
		return err
	}

	log.Info("Creating port forwarding rule for docker port ...")
	if err := d.configurePortForwardingRule(dockerPort, dockerPort); err != nil {
		return err
	}

	if d.SwarmMaster {
		log.Info("Creating port forwarding rule for swarm port ...")
		if err := d.configurePortForwardingRule(swarmPort, swarmPort); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) createSecurityGroup() error {
	log.Debugf("Creating security group ...")
	cs := d.getClient()

	p1 := cs.SecurityGroup.NewCreateSecurityGroupParams(d.MachineName)
	if d.ProjectID != "" {
		p1.SetProjectid(d.ProjectID)
	}
	if _, err := cs.SecurityGroup.CreateSecurityGroup(p1); err != nil {
		return err
	}

	p2 := cs.SecurityGroup.NewAuthorizeSecurityGroupIngressParams()
	p2.SetSecuritygroupname(d.MachineName)
	p2.SetProtocol("tcp")
	p2.SetCidrlist(d.CIDRList)

	p2.SetStartport(22)
	p2.SetEndport(22)
	if d.ProjectID != "" {
		p2.SetProjectid(d.ProjectID)
	}
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	p2.SetStartport(dockerPort)
	p2.SetEndport(dockerPort)
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	if d.SwarmMaster {
		p2.SetStartport(swarmPort)
		p2.SetEndport(swarmPort)
		if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) deleteSecurityGroup() error {
	log.Debugf("Deleting security group ...")
	cs := d.getClient()

	p := cs.SecurityGroup.NewDeleteSecurityGroupParams()
	p.SetName(d.MachineName)
	if d.ProjectID != "" {
		p.SetProjectid(d.ProjectID)
	}
	if _, err := cs.SecurityGroup.DeleteSecurityGroup(p); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createTags() error {
	log.Info("Creating resource tags ...")
	cs := d.getClient()
	tags := make(map[string]string)
	for _, t := range d.Tags {
		parts := strings.SplitN(t, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid resource tags format, each tag must be on the format KEY:VALUE")
		}
		tags[parts[0]] = parts[1]
	}
	params := cs.Resourcetags.NewCreateTagsParams([]string{d.ID}, "UserVm", tags)
	_, err := cs.Resourcetags.CreateTags(params)
	return err
}

func (d *Driver) setParams(c *cloudstack.CloudStackClient, p interface{}) error {
	if o, ok := p.(interface {
		SetProjectid(string)
	}); ok && d.ProjectID != "" {
		o.SetProjectid(d.ProjectID)
	}
	if o, ok := p.(interface {
		SetZoneid(string)
	}); ok && d.ZoneID != "" {
		o.SetZoneid(d.ZoneID)
	}
	return nil
}
