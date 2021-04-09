package iotcore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	DefaultHost     = "mqtt.googleapis.com"
	DefaultPort     = "8883"
	DefaultUsername = "unused"
	algorithm       = "RS256"
	qos             = 1
)

type IoTCoreClient interface {
	Publish(message string) error
}

type ioTCoreClient struct {
	host           string
	port           string
	projectID      string
	region         string
	registryID     string
	deviceID       string
	privateKeyPath string
	topic          struct {
		config    string
		telemetry string
	}
	clientID string
	username string
	password string
}

func NewIoTCoreClient(ProjectID string, Region string, RegistryID string, DeviceID string, PrivateKeyPath string) IoTCoreClient {
	icc := &ioTCoreClient{
		host:           DefaultHost,
		port:           DefaultPort,
		projectID:      ProjectID,
		region:         Region,
		registryID:     RegistryID,
		deviceID:       DeviceID,
		privateKeyPath: PrivateKeyPath,
		username:       DefaultUsername,
	}
	icc.topic.config = fmt.Sprintf("/devices/%v/config", icc.deviceID)
	icc.topic.telemetry = fmt.Sprintf("/devices/%v/events", icc.deviceID)
	icc.clientID = fmt.Sprintf("projects/%v/locations/%v/registries/%v/devices/%v", icc.projectID, icc.region, icc.registryID, icc.deviceID)
	return icc
}

func (icc *ioTCoreClient) createJWT(expiration time.Duration) error {
	claims := jwt.StandardClaims{
		Audience:  icc.projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(expiration).Unix(),
	}
	log.Println(claims)
	keyBytes, err := ioutil.ReadFile(icc.privateKeyPath)
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile(icc.privateKeyPath): %v", err)
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims
	privkey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM(keyBytes): %v", err)
	}

	icc.password, err = token.SignedString(privkey)
	if err != nil {
		return fmt.Errorf("token.SignedString(privkey): %v", err)
	}
	return nil
}

func (icc *ioTCoreClient) Publish(message string) error {
	if err := icc.createJWT(time.Minute * 20); err != nil {
		return fmt.Errorf("icc.CreateJWT(time.Minute * 20): %v", err)
	}

	server := fmt.Sprintf("tls://%v:%v", icc.host, icc.port)
	fmt.Println(server)

	caCert, err := ioutil.ReadFile(os.Getenv("CA_CERT_PATH"))
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile(os.Getenv(\"CA_CERT_PATH\"): %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{},
		MinVersion:         tls.VersionTLS12,
	}
	opts := mqtt.NewClientOptions().
		AddBroker(server).
		SetClientID(icc.clientID).
		SetUsername(icc.username).
		SetTLSConfig(tlsConfig).
		SetPassword(icc.password)

	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("[handler] Topic: %v\n", msg.Topic())
		fmt.Printf("[handler] Payload: %v\n", msg.Payload())
	})

	cli := mqtt.NewClient(opts)
	if tok := cli.Connect(); tok.Wait() && tok.Error() != nil {
		return tok.Error()
	}

	for i := 0; i < 5; i++ {
		str := fmt.Sprintf("Message:%s", message)
		cli.Publish(icc.topic.telemetry, qos, false, str)
		time.Sleep(time.Millisecond * 50)
	}

	cli.Disconnect(2000)
	return nil
}
