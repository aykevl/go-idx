package idx

import (
	"errors"

	"github.com/beevik/etree"
)

type IDealClient struct {
	CommonClient
}

// A single iDeal transaction.
type IDealTransaction struct {
	client                  *IDealClient
	msg                     *etree.Element
	issuerAuthenticationURL string
	transactionID           string
}

// The returned transaction status after a status request. Fields besides Status
// are only set when Status equals Success.
type IDealTransactionStatus struct {
	Status       TransactionStatus
	ConsumerName string // ConsumerName: the full name of one or even multiple consumers.
	ConsumerIBAN string
	ConsumerBIC  string
	Amount       string // for example, "1.00"
	Currency     string // for example, "EUR"
}

func (c *IDealClient) createMessage(tag string) *etree.Element {
	msg := c.CommonClient.createMessage(tag)
	msg.CreateAttr("xmlns", "http://www.idealdesk.com/ideal/messages/mer-acq/3.3.1")
	msg.CreateAttr("version", "3.3.1")
	return msg
}

func (c *IDealClient) request(msg string) (*etree.Document, error) {
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
// It should be executed somewhere between once a day and once a month, and
// specifically must not be executed on each request. This means you have to
// cache the returned list of banks.
func (c *IDealClient) DirectoryRequest() (*Directory, error) {
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

// Request the status of a transaction. Returns an error on network/protocol
// errors. Note that you must check the Status field manually.
//
// There are limits on how often you can call this function, see the
// specification for details ("Collection duty").
func (c *IDealClient) TransactionStatus(trxid string) (*IDealTransactionStatus, error) {
	msg := c.createMessage("AcquirerStatusReq")
	msg.CreateElement("Transaction").CreateElement("transactionID").SetText(trxid)
	doc, err := c.request(c.signMessage(msg))
	if err != nil {
		return nil, err
	}
	response, err := c.validateMessage(doc)
	if err != nil {
		return nil, err
	}

	transactionID := response.FindElement("/Transaction/transactionID").Text()
	if transactionID != trxid {
		return nil, errors.New("idx: returned transaction ID does not match")
	}

	statusString := response.FindElement("/Transaction/status").Text()
	var status TransactionStatus
	switch statusString {
	case "Success":
		status = Success
	case "Cancelled":
		status = Cancelled
	case "Expired":
		status = Expired
	case "Failure":
		status = Failure
	case "Open":
		status = Open
	default:
		status = InvalidStatus
	}

	if status == InvalidStatus {
		// Invalid status (not one of the statuses specified in the MIR).
		return nil, errors.New("ideal: invalid status: " + statusString)
	} else if status == Success {
		// Valid response, transaction was successful.
		return &IDealTransactionStatus{
			Status:       status,
			ConsumerName: response.FindElement("/Transaction/consumerName").Text(),
			ConsumerIBAN: response.FindElement("/Transaction/consumerIBAN").Text(),
			ConsumerBIC:  response.FindElement("/Transaction/consumerBIC").Text(),
			Amount:       response.FindElement("/Transaction/amount").Text(),
			Currency:     response.FindElement("/Transaction/currency").Text(),
		}, nil
	} else {
		// Valid response, but status was not "Success".
		return &IDealTransactionStatus{
			Status: status,
		}, nil
	}

}

// Create a transaction object but do not start it.
//
// The issuer is the bank ID selected by the consumer, purchaseID is an unique
// number for this transaction in your system and will appear in the consumer's
// bank notes, description is the text to show in the client's bank notes, and
// entranceCode is a session token you can use to resume the (possibly expired)
// session when the consumer returns to your website.
func (c *IDealClient) NewTransaction(issuer, purchaseID, amount, description, entranceCode string) *IDealTransaction {
	msg := c.createMessage("AcquirerTrxReq")
	merchantEl := msg.FindElement("/Merchant")
	merchantEl.CreateElement("merchantReturnURL").SetText(c.ReturnURL)
	issuerEl := msg.CreateElement("Issuer")
	issuerEl.CreateElement("issuerID").SetText(issuer)
	msg.InsertChild(merchantEl, issuerEl) // order matters: Issuer must occur before Merchant
	transaction := msg.CreateElement("Transaction")
	transaction.CreateElement("purchaseID").SetText(purchaseID)
	transaction.CreateElement("amount").SetText(amount)
	transaction.CreateElement("currency").SetText("EUR")
	transaction.CreateElement("language").SetText("nl")
	transaction.CreateElement("description").SetText(description)
	transaction.CreateElement("entranceCode").SetText(entranceCode)
	return &IDealTransaction{client: c, msg: msg}
}

// Start a transaction.
//
// Note that you must save the transaction ID upon creation, so that it can be
// closed after a day or so when the client closes the browser window/tab before
// completion. Also, you are required to deliver something when the transaction
// was completed (even when the consumer doesn't return to your website after
// completion), see the documentation for details.
func (t *IDealTransaction) Start() error {
	// create a signed message and do a request
	doc, err := t.client.request(t.client.signMessage(t.msg))
	if err != nil {
		return err
	}

	// validate the response message
	response, err := t.client.validateMessage(doc)
	if err != nil {
		return err
	}

	// extract the transaction ID and the URL to redirect to
	t.issuerAuthenticationURL = response.FindElement("/Issuer/issuerAuthenticationURL").Text()
	t.transactionID = response.FindElement("/Transaction/transactionID").Text()

	return nil
}

// Return the URL to redirect the user to to start authentication.
func (t *IDealTransaction) IssuerAuthenticationURL() string {
	return t.issuerAuthenticationURL
}

// Return the transaction ID, useful for logging.
func (t *IDealTransaction) TransactionID() string {
	return t.transactionID
}
