package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/nustiueudinastea/protoslib-go"
	"github.com/urfave/cli"
	//lego "github.com/xenolf/lego"
)

var log = logrus.New()

func waitQuit(pclient protos.Protos) {
	sigchan := make(chan os.Signal, 10)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan
	log.Info("Deregisterting as certificate provider")
	err := pclient.DeregisterProvider("dns")
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
	pclient := protos.NewClient(protosURL, appID)

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

	for {
		log.Debug("Doing bogus loop step")
		time.Sleep(interval * time.Second)
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
