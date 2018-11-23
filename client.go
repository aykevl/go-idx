// Package idx implements the iDeal and iDIN protocols, as used by Dutch banks.
//
// The iDeal specification (merchant integration guide) can be viewed online
// from this URL:
// https://www.rabobank.nl/images/ideal_merchant_integration_guide_29696264.pdf
//
// The iDIN specification is not available online, but can be requested with
// this form:
// https://www.idin.nl/identiteitdienstverleners/veelgestelde-vragen/documentatie-aanvragen/
//
// Note that you should take a look at this documentation before using this
// library, as banks will often require you to follow certain practices! For
// example, every transaction *must* be closed, even if it is not successful (or
// if the consumer closes the web browser during the iDeal/iDIN transaction).
package idx

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

type TransactionStatus int

// TransactionStatus is an enum of the possible statuses of an iDeal/iDIN
// transaction.
const (
	InvalidStatus TransactionStatus = iota
	Success
	Cancelled
	Expired
	Failure
	Open
)

func (status TransactionStatus) String() string {
	switch status {
	case Success:
		return "Success"
	case Cancelled:
		return "Cancelled"
	case Expired:
		return "Expired"
	case Failure:
		return "Failure"
	case Open:
		return "Open"
	default:
		// Not returned in the iDeal/iDIN protocol.
		return "InvalidStatus"
	}
}

// AcquirerError may be returned by any API call to an iDeal/iDIN server.
type AcquirerError struct {
	ErrorCode       string // Short error code.
	ErrorMessage    string // Short human-readable error message.
	ErrorDetail     string // Longer human-readable error message, e.g. the origin of the error.
	ConsumerMessage string // The message to display on your website to the consumer.
}

// Error returns a string with the error code, error message and error detail
// string.
//
// Note that when you hit this error, you should display the ConsumerMessage
// field of this struct to the user.
func (e AcquirerError) Error() string {
	return "idx: " + e.ErrorCode + ": " + e.ErrorMessage + " (" + e.ErrorDetail + ")"
}

// A Client implements common functionality between the iDeal and iDIN
// protocols.
type Client interface {
	DirectoryRequest() (*Directory, error)
}

// The common client implements common functionality between iDeal and iDIN.
type CommonClient struct {
	BaseURL      string            // The API endpoint to use, as provided by your bank.
	MerchantID   string            // Merchant ID, as provided by your bank.
	SubID        string            // "0" if you don't use sub IDs.
	ReturnURL    string            // The URL to return to after the iDeal/iDIN transaction is complete.
	Certificate  tls.Certificate   // Your certificate, with which to sign outgoing messages.
	AcquirerCert *x509.Certificate // The certificate of the bank, with which to verify incoming messages.
}

func (c *CommonClient) createMessage(tag string) *etree.Element {
	msg := &etree.Element{
		Tag: tag,
	}
	msg.CreateElement("createDateTimestamp").SetText(time.Now().UTC().Format(time.RFC3339))
	merchant := msg.CreateElement("Merchant")
	merchant.CreateElement("merchantID").SetText(c.MerchantID)
	merchant.CreateElement("subID").SetText(c.SubID)
	return msg
}

func (c *CommonClient) request(msg string) (*etree.Document, error) {
	body := bytes.NewBufferString(msg)
	req, err := http.NewRequest("POST", c.BaseURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("Version", "1.0")
	req.Header.Add("Encoding", "UTF-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("idx: HTTP error: " + resp.Status)
	}

	doc := etree.NewDocument()
	_, err = doc.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func (c *CommonClient) signMessage(msg *etree.Element) string {
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(c.Certificate))
	ctx.Prefix = ""
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(msg)
	if err != nil {
		panic(err)
	}

	keyName := sha1.Sum(c.Certificate.Certificate[0])
	keyNameString := strings.ToUpper(hex.EncodeToString(keyName[:]))

	keyInfo := signed.FindElement("/Signature/KeyInfo")
	// remove existing children
	for _, child := range keyInfo.ChildElements() {
		keyInfo.RemoveChild(child)
	}
	// Insert custom KeyName element
	keyInfo.CreateElement("KeyName").SetText(keyNameString)

	doc := etree.NewDocument()
	doc.SetRoot(signed)
	str, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}

	return xml.Header + str
}

func (c *CommonClient) validateMessage(msg *etree.Document) (*etree.Element, error) {
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{c.AcquirerCert},
	})

	return ctx.Validate(msg.ChildElements()[0])
}

func (c *CommonClient) parseDirectoryRequest(msg *etree.Element) *Directory {
	directory := &Directory{
		Issuers: make(map[string][]Issuer),
	}
	for _, countryEl := range msg.FindElements("/Directory/Country") {
		countryName := countryEl.FindElement("/Directory/Country/countryNames").Text()
		for _, issuerEl := range countryEl.FindElements("/Directory/Country/Issuer") {
			issuerID := issuerEl.FindElement("/Directory/Country/Issuer/issuerID").Text()
			issuerName := issuerEl.FindElement("/Directory/Country/Issuer/issuerName").Text()
			directory.Issuers[countryName] = append(directory.Issuers[countryName], Issuer{issuerID, issuerName})
		}
	}
	return directory
}

// The directory listing, as returned from a directory request.
// It is a map from country name to a list of issuers in that country.
type Directory struct {
	Issuers map[string][]Issuer `json:"issuers"`
}

// A single issuer (bank), as returned in a directory request.
type Issuer struct {
	IssuerID   string `json:"issuerID"`   // BIC
	IssuerName string `json:"issuerName"` // Human-readable name
}
