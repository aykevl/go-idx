package idx

import (
	"crypto/rsa"
	"errors"
	"strconv"

	"github.com/aykevl/go-xmlenc"
	"github.com/beevik/etree"
)

type IDINAttribute int

// Bits in the bitmask of requested attributes. Request multiple attribute kinds
// by ORing them toghether.
const (
	IDINServiceIDBIN         IDINAttribute = 1 << 14 // 16384
	IDINServiceIDName        IDINAttribute = 1 << 12 // 4096
	IDINServiceIDAddress     IDINAttribute = 1 << 10 // 1024
	IDINServiceIDDateOfBirth IDINAttribute = 7 << 6  // 64 | 128 | 256 = 448
	IDINServiceIDGender      IDINAttribute = 1 << 4  // 16
	IDINServiceIDTelephone   IDINAttribute = 1 << 2  // 4
	IDINServiceIDEmail       IDINAttribute = 1 << 1  // 2
)

type IDINClient struct {
	CommonClient
}

type IDINTransaction struct {
	client                  *IDINClient
	msg                     *etree.Element
	issuerAuthenticationURL string
	transactionID           string
}

// IDINTransactionStatus is the result of doing a status request of an iDIN
// transaction. The returned attributes are only present after a successful
// transaction.
type IDINTransactionStatus struct {
	Status     TransactionStatus
	Attributes map[string]string
}

func (c *IDINClient) createMessage(tag string) *etree.Element {
	msg := c.CommonClient.createMessage(tag)
	msg.CreateAttr("xmlns", "http://www.betaalvereniging.nl/iDx/messages/Merchant-Acquirer/1.0.0")
	msg.CreateAttr("version", "1.0.0")
	msg.CreateAttr("productID", "NL:BVN:BankID:1.0")
	return msg
}

func (c *IDINClient) request(msg string) (*etree.Document, error) {
	doc, err := c.CommonClient.request(msg)
	if doc != nil && doc.ChildElements()[0].Tag == "AcquirerErrorRes" {
		return nil, &AcquirerError{
			ErrorCode:       doc.FindElement("/AcquirerErrorRes/Error/errorCode").Text(),
			ErrorMessage:    doc.FindElement("/AcquirerErrorRes/Error/errorMessage").Text(),
			ErrorDetail:     doc.FindElement("/AcquirerErrorRes/Error/errorDetail").Text(),
			ConsumerMessage: doc.FindElement("/AcquirerErrorRes/Error/consumerMessage").Text(),
		}
	}
	return doc, err
}

// Do a directory request, to get a list of banks.
//
// It should be issued at least once a week, but may not be issued very often
// (e.g. not every request). The recommended interval is once a week, see the
// iDIN specification for details ("iDIN Directory Protocol").
func (c *IDINClient) DirectoryRequest() (*Directory, error) {
	msg := c.createMessage("DirectoryReq")
	doc, err := c.request(c.signMessage(msg))
	if err != nil {
		return nil, err
	}
	response, err := c.validateMessage(doc)
	if err != nil {
		return nil, err
	}
	return c.parseDirectoryRequest(response), nil
}

// Request the status of a transaction. Returns an error on
// network/protocol/signature errors. Note that when it does not return an
// error, the status may still be something other than "Success", you will have
// to handle each possible status.
//
// This call may only be done once upon redirection from the consumer bank. See
// 11.5 "Restrictions on AcquirerStatusReq" in the iDIN specification for
// details.
func (c *IDINClient) TransactionStatus(trxid string) (*IDINTransactionStatus, error) {
	msg := c.createMessage("AcquirerStatusReq")
	msg.CreateElement("Transaction").CreateElement("transactionID").SetText(trxid)
	doc, err := c.request(c.signMessage(msg))
	if err != nil {
		return nil, err
	}

	// Note, this does not work yet at the moment due to issues in the xmlenc
	// library. You can use this line instead of validating the return message
	// to work around the issue:
	// WARNING: DO NOT DO THIS IN PRODUCTION! Fix the bug first!
	//root := doc.Element
	root, err := c.validateMessage(doc)
	if err != nil {
		return nil, err
	}

	transactionID := root.FindElement("/AcquirerStatusRes/Transaction/transactionID").Text()
	if transactionID != trxid {
		return nil, errors.New("idx: returned transaction ID does not match")
	}

	statusCodeEl := root.FindElement("/AcquirerStatusRes/Transaction/container/Response/Status/StatusCode")
	var status TransactionStatus
	statusString := statusCodeEl.SelectAttrValue("Value", "")
	// WARNING: untested status strings.
	switch statusString {
	case "urn:oasis:names:tc:SAML:2.0:status:Success":
		status = Success
	case "urn:oasis:names:tc:SAML:2.0:status:Cancelled":
		status = Cancelled
	case "urn:oasis:names:tc:SAML:2.0:status:Expired":
		status = Expired
	case "urn:oasis:names:tc:SAML:2.0:status:Failure":
		status = Failure
	case "urn:oasis:names:tc:SAML:2.0:status:Open":
		status = Open
	default:
		return nil, errors.New("idin: invalid status: " + statusString)
	}

	result := &IDINTransactionStatus{
		Status: status,
	}
	if status == Success {
		result.Attributes = make(map[string]string)
		for _, el := range root.FindElements("/AcquirerStatusRes/Transaction/container/Response/Assertion/AttributeStatement/EncryptedAttribute/EncryptedData") {
			el, err := xmlenc.DecryptElement(el, c.Certificate.PrivateKey.(*rsa.PrivateKey))
			if err != nil {
				return nil, err
			}
			key := el.FindElement("Attribute").SelectAttrValue("Name", "")
			value := el.FindElement("Attribute/AttributeValue").Text()
			result.Attributes[key] = value
		}
	}
	return result, nil
}

// Create a transaction object but do not start it.
//
// The issuer is the consumer-selected bank, the entranceCode is a session token
// to resume an existing session so the user doesn't get logged out during the
// iDIN transaction, and attributes is a set of flags indicating the requested
// attributes (request multiple attributes by ORing them together).
func (c *IDINClient) NewTransaction(issuer, entranceCode, id string, attributes IDINAttribute) *IDINTransaction {
	msg := c.createMessage("AcquirerTrxReq")
	merchantEl := msg.FindElement("/Merchant")
	merchantEl.CreateElement("merchantReturnURL").SetText(c.ReturnURL)
	issuerEl := msg.CreateElement("Issuer")
	issuerEl.CreateElement("issuerID").SetText(issuer)
	msg.InsertChild(merchantEl, issuerEl) // order matters: Issuer must occur before Merchant
	transaction := msg.CreateElement("Transaction")
	transaction.CreateElement("language").SetText("nl")
	transaction.CreateElement("entranceCode").SetText(entranceCode)
	container := transaction.CreateElement("container")
	samlAuthRequest := container.CreateElement("samlp:AuthnRequest")
	samlAuthRequest.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	samlAuthRequest.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	samlAuthRequest.CreateAttr("ID", id)
	samlAuthRequest.CreateAttr("Version", "2.0")
	samlAuthRequest.CreateAttr("IssueInstant", msg.FindElement("/createDateTimestamp").Text())
	samlAuthRequest.CreateAttr("ProtocolBinding", "nl:bvn:bankid:1.0:protocol:iDx")
	samlAuthRequest.CreateAttr("AssertionConsumerServiceURL", c.ReturnURL)
	samlAuthRequest.CreateAttr("AttributeConsumingServiceIndex", strconv.Itoa(int(attributes)))
	samlAuthRequest.CreateElement("saml:Issuer").SetText(c.MerchantID)
	context := samlAuthRequest.CreateElement("samlp:RequestedAuthnContext")
	context.CreateAttr("Comparison", "minimum")
	context.CreateElement("saml:AuthnContextClassRef").SetText("nl:bvn:bankid:1.0:loa3")
	return &IDINTransaction{client: c, msg: msg}
}

// Start a transaction.
//
// Note that you must save the transaction ID upon creation, so that it can be
// closed after a day or so when the client closes the browser window/tab before
// completion.
func (t *IDINTransaction) Start() error {
	doc, err := t.client.request(t.client.signMessage(t.msg))
	if err != nil {
		return err
	}
	response, err := t.client.validateMessage(doc)
	if err != nil {
		return err
	}

	t.issuerAuthenticationURL = response.FindElement("/Issuer/issuerAuthenticationURL").Text()
	t.transactionID = response.FindElement("/Transaction/transactionID").Text()

	return nil
}

// Return the URL to which to redirect the consumer to start the iDIN process
// for the consumer.
func (t *IDINTransaction) IssuerAuthenticationURL() string {
	return t.issuerAuthenticationURL
}

// Return the transaction ID, useful for logging.
func (t *IDINTransaction) TransactionID() string {
	return t.transactionID
}
