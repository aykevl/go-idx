# iDeal and iDIN

[![GoDoc](https://godoc.org/github.com/aykevl/go-idx?status.svg)](https://godoc.org/github.com/aykevl/go-idx)

This is a Go library implementing the iDeal and iDIN protocols, as used by Dutch
(and other) banks.

## Current status

This library requires good
[XML signature](https://en.wikipedia.org/wiki/XML_Signature) support.
Unfortunately, the best library I could find
([github.com/russellhaering/goxmldsig](https://github.com/russellhaering/goxmldsig))
doesn't work well enough. Therefore, I [patched
it](https://github.com/aykevl/goxmldsig/commits/idx-hacks) to get iDEAL to work.
Unfortunately, iDIN support needs even more changes so is not supported at this
time.

## Usage

```go
// Configure a client.
ideal := &idx.IDealClient{
    CommonClient: idx.CommonClient{
        BaseURL:    "", // provided by your bank
        MerchantID: "", // provided by your bank
        SubID:      "", // provided by your bank
        ReturnURL:  "", // the URL of your webapp that you will return to
        Certificate: tls.Certificate{ // keypair genered by you
            Certificate: [][]byte{cert}, // uploaded to the bank
            PrivateKey:  sk,
        },
        AcquirerCert: iDealAcquirerCert, // certificate provided by your bank
    },
}

// Create a transaction.
transaction := ideal.NewTransaction("<bankid>", "<purchaseID>", "1.00", "<description>", "<entranceCode>")
err := transaction.Start()
// handle error

// redirect the client to the bank
redirect(transaction.IssuerAuthenticationURL())

// after the client returns:
response, err := ideal.TransactionStatus(trxid)
// handle error
// do something with the response (check the iDEAL docs for requirements)
```

## License

This library is licensed under the BSD 2-clause license. See LICENSE.txt for
details.
