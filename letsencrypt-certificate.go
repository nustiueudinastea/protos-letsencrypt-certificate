package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nustiueudinastea/protos/resource"

	protos "github.com/nustiueudinastea/protoslib-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	acme "github.com/xenolf/lego/acme"
)

var log = logrus.New()

type MyUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type ProtosProvider struct {
	Domain     string
	PClient    protos.Protos
	Challenges map[string]*resource.Resource
	User       MyUser
}

// Present creates the dns challenge to prove domain ownership to Let's Encrypt
func (pp *ProtosProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := acme.DNS01Record(domain, keyAuth)
	host := strings.TrimSuffix(fqdn, "."+pp.Domain+".")
	log.Debugf("Creating DNS challenge for domain %s with token %s", domain, value)
	dnsresource := resource.DNSResource{
		Host:  host,
		Value: value,
		Type:  "txt",
		TTL:   ttl,
	}
	rscreq := resource.Resource{
		Type:  resource.DNS,
		Value: &dnsresource,
	}
	rsc, err := pp.PClient.CreateResource(rscreq)
	if err != nil {
		return err
	}
	pp.Challenges[token] = rsc
	log.Debugf("Requested DNS resource %v", dnsresource)
	created := false
	for created == false {
		rsc, err = pp.PClient.GetResource(rsc.ID)
		if err != nil {
			return err
		}
		if rsc.Status == resource.Created {
			created = true
			log.Debug("DNS resource has been created")
			continue
		}
		log.Debugf("Waiting for dns record %s(%s) to be created", dnsresource.Host, dnsresource.Value)
		time.Sleep(5 * time.Second)
	}
	return nil
}

// CleanUp is triggered once the certificate has been created, to clean up the created dns records
func (pp *ProtosProvider) CleanUp(domain, token, keyAuth string) error {
	log.Debugf("Deleting DNS resource for challenge %s for domain %s %s", keyAuth, domain, token)
	err := pp.PClient.DeleteResource(pp.Challenges[token].ID)
	if err != nil {
		return err
	}
	return nil
}

// Timeout returns the timeout duration for waiting for DNS propagation and the interval to check it
func (pp *ProtosProvider) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Minute, 20 * time.Second
}

func (pp *ProtosProvider) requestCertificate(domains []string) (*acme.CertificateResource, error) {

	const rsaKeySize = 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, err
	}

	myUser := MyUser{
		Email: "alex@protos.io",
		key:   privateKey,
	}

	client, err := acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", &myUser, acme.RSA2048)
	if err != nil {
		return nil, err
	}

	reg, err := client.Register()
	if err != nil {
		return nil, err
	}

	myUser.Registration = reg
	err = client.AgreeToTOS()
	if err != nil {
		return nil, err
	}

	err = client.SetChallengeProvider(acme.DNS01, pp)
	if err != nil {
		return nil, err
	}
	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

	bundle := false
	certificate, failures := client.ObtainCertificate(domains, bundle, nil, false)
	if len(failures) > 0 {
		for _, fail := range failures {
			log.Error(fail)
		}
		return nil, errors.New("Could not obtain certificate")
	}

	log.Debugf("Certificate for domain %s has been created", certificate.Domain)
	return &certificate, nil
}

func waitQuit(pclient protos.Protos) {
	sigchan := make(chan os.Signal, 10)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan
	log.Info("Deregisterting as certificate provider")
	err := pclient.DeregisterProvider("certificate")
	if err != nil {
		log.Error("Could not deregister as certificate provider: ", err.Error())
	}
	log.Info("Stopping Letsencrypt provider")

	os.Exit(0)
}

func activityLoop(interval time.Duration, protosURL string) {

	appID, err := protos.GetAppID()
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Starting with a check interval of ", interval*time.Second)
	log.Info("Using ", protosURL, " to connect to Protos.")

	// Clients to interact with Protos and Namecheap
	certProvider := ProtosProvider{}
	pclient := protos.NewClient(protosURL, appID)
	certProvider.PClient = pclient
	certProvider.Challenges = make(map[string]*resource.Resource)

	go waitQuit(pclient)

	// Each service provider needs to register with protos
	log.Info("Registering as certificate provider")
	time.Sleep(4 * time.Second) // Giving Docker some time to assign us an IP
	err = pclient.RegisterProvider("certificate")
	if err != nil {
		if strings.Contains(err.Error(), "already registered") {
			log.Error("Failed to register as certificate provider: ", strings.TrimRight(err.Error(), "\n"))
		} else {
			log.Fatal("Failed to register as certificate provider: ", err)
		}
	}

	log.Debug("Getting domain")
	domain, err := pclient.GetDomain()
	if err != nil {
		log.Error(err)
	}
	log.Debugf("Using domain %s", domain)
	certProvider.Domain = domain

	first := true
	for {
		if first == false {
			time.Sleep(interval * time.Second)
		}
		first = false

		resources, err := pclient.GetResources()
		if err != nil {
			log.Error(err)
			continue
		}
		for _, rsc := range resources {
			if rsc.Status == resource.Requested {
				log.Debugf("New certificate resquest with resource %s", rsc.ID)
				val := rsc.Value.(*resource.CertificateResource)
				fqdns := []string{}
				for _, subdomain := range val.Domains {
					if subdomain == "@" || strings.ToLower(subdomain) == strings.ToLower(certProvider.Domain) {
						fqdns = append(fqdns, certProvider.Domain)
					} else {
						fqdns = append(fqdns, subdomain+"."+certProvider.Domain)
					}
				}
				certificate, err := certProvider.requestCertificate(fqdns)
				if err != nil {
					log.Debugf("Error while creating certificate for resource %s: %s", rsc.ID, err.Error())
					continue
				}

				val.Certificate = certificate.Certificate
				val.PrivateKey = certificate.PrivateKey
				val.IssuerCertificate = certificate.IssuerCertificate
				val.CSR = certificate.CSR
				err = pclient.UpdateResourceValue(rsc.ID, val)
				if err != nil {
					log.Errorf("Failed to update value for resource %s: %s", rsc.ID, err.Error())
					continue
				}
				err = pclient.SetResourceStatus(rsc.ID, "created")
				if err != nil {
					log.Errorf("Failed to set status for resource %s: %s", rsc.ID, err.Error())
					continue
				}

			}
		}
	}

}

func main() {

	app := cli.NewApp()
	app.Name = "letsencrypt-certificate"
	app.Author = "Alex Giurgiu"
	app.Email = "alex@giurgiu.io"
	app.Version = "0.0.1"

	var protosURL string
	var interval int
	var loglevel string

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:        "interval",
			Value:       30,
			Usage:       "Specify check interval in seconds",
			Destination: &interval,
		},
		cli.StringFlag{
			Name:        "loglevel",
			Value:       "info",
			Usage:       "Specify log level: debug, info, warn, error",
			Destination: &loglevel,
		},
		cli.StringFlag{
			Name:        "protosurl",
			Value:       "http://protos:8080/",
			Usage:       "Specify url used to connect to Protos API",
			Destination: &protosURL,
		},
	}

	app.Before = func(c *cli.Context) error {
		level, err := logrus.ParseLevel(loglevel)
		if err != nil {
			return err
		}
		log.SetLevel(level)
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:  "start",
			Usage: "start the Letsencrypt certificate service",
			Action: func(c *cli.Context) {
				activityLoop(time.Duration(interval), protosURL)
			},
		},
	}

	app.Run(os.Args)
}
