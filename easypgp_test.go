package easypgp

import "testing"

const (
	message  = "Hello, EasyPGP!"
	pubkey1  = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFkLOysBCAC5OXFJHJMFZfBTAb1+tWI9BJjnvBONzD4TfcqlInE+KOFHtTSi\nt6nOWvOOVrcjf8tR5SXlykN3yjyaaF21eAcb02/oDHxMzPdZYhGzASR2ayXzg5W6\nIi0yG1+mh7hBOe9Bi2Xwu+Al+iwy8jxsqZss/mdpvjuQpaj+tEXmPVE7jRME6bGn\nN9zocexwxI4BFOPDtpxYLS1QQVw43dTY49ZOVsfXBGiQGJ2oy3QRX5FjZZymcVEt\nZsU3nbjzIX0X8rYzLxaDEMRfn1SNZxBVPPUy78Sg96HdvK0/Is2YSkkgvPbwkbRL\nEA+rvy4EzAAtmUwHkNjD3fkDfhrjO9Ub9QINABEBAAG0CnRlc3Qga2V5IDGJAVQE\nEwEIAD4WIQQ0/l+w4pCD895bDsqS3b0lwo0KpgUCWQs7KwIbAwUJA8JnAAULCQgH\nAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRCS3b0lwo0Kpn5MCACbMWDZmvqJGLO6nDo/\nCaKCfrYUEiI3QBdRCqDuq/MoFevsC/CeY3amc1eQRoUzEkF55UKoUpZcVCE3hzVd\nagNpxhPj5vM7xpYXpUsSpl22ulXn1IS4eXxNE6VfO5LCumCofbAZwxiUEncS8yC/\n8LpmWzYzNkrK2XOlU+YvxSKIjUxa3pflhxLHBb+tIrfID0p2UtFbXbXo6XS5Hw2c\n+epcOrBKKKDHND4aGuGhgvLm57Az+yrnZAHS/6EW5nJnzzDkElF6Zak8GCsf51sI\n6WYSw5EUkv2XCFrA+kmZGbmrtAipifmqLTr1BIUuTRMdtk+LHfV3fomE8z3bDcnW\nuTdIuQENBFkLOysBCADG8vOcigYfT+c6E9bA/Y34CtqjejQz2ShYXYFKMgEI52kG\njFvIYM+yFkhOJxepA8O26Kk9s2gEPu2RDK4E4XgZK9W+x2XnDOpopnOw9sqs/E2R\ncgL8SMdUnrY6Tpbv4D+pbpJTd8lAKT6R8JechaVABj/+Im3IWb6kqvyCWBAAJiDk\nWfHEinnuuPkqAiYbZTFoiD0wQt1nwExpaU09u0c44Ww9F7xKzlCfn+lYqr6E+lcU\nThbLB+RZD0FyZVcXeQvTejNHQoLPLma7CYM8ohgkR6vLxsLA4cQxXwT4NJpoY2xG\nsS5h95rdrt+J9rW4dYfgw/Q4l6ePFwp22qkF5REfABEBAAGJATwEGAEIACYWIQQ0\n/l+w4pCD895bDsqS3b0lwo0KpgUCWQs7KwIbDAUJA8JnAAAKCRCS3b0lwo0KplG4\nCACOFwo+JRh8PixYHbpgt3rkuyVctFa62tariv8T+iKstt25gIw7mOTflq2RfSg2\nv/wmGxLwYeCjHPDL7aork6yEclhjVRHVwMwOg5s2NWhCmBpYivFKFaMeDfjYzc5A\nY3ikpByr5egqvCT9SX3OHXzCHrOmqZEXcDnVzq9aSyvQzEE8OvKQXWYa0PgdZ5iN\n4l6empjXU703m4iy4ph/CrbJKu6ynf8OUGHODEgJbOGCNyXsYbOzbdP138UBFq4Q\n/MFKdyNhc0OhN2uYxQpLVFpR9u9IQp+Shx1xpf8VGK/j8SWAVdRaxkAZvc4YTmGT\n0YASGNrrORVa5KsKkJ+CPFN+\n=8qiG\n-----END PGP PUBLIC KEY BLOCK-----\n"
	privkey1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n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\nvc4YTmGT0YASGNrrORVa5KsKkJ+CPFN+\n=6+dj\n-----END PGP PRIVATE KEY BLOCK-----\n"

	pubkey2  = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFkLOz0BCADO/Sv/iRWaJvBqFv+RCzkWGLO2B2l1v5fswKh3FXojZnvBkPDo\nrpRt4tL2f604pOYOcFRKaQUuJECBS3YDFWqr4vDXt//tvTwmY5gYFOgzt4p8opvK\naUljzGc07dERclsAidyTXAz5qolT2F2Ed6odJcCS5m5oYziMSEMJW+kweUR27VRD\npi0utXV7zeafKUdoLTwadXD0YRETX7hFmCWaJI4blISHOC82rKN2UNvWRCf5zSie\nXuu23xoz0JqPEVDBeae0S3gbZ+JbwFEdVOcPsovw/oesjx3EpcKpMHrSBAjU7000\neBBHPkqAs/ZblmhzHvnCJB4CbK5ZKXLo8AvpABEBAAG0CnRlc3Qga2V5IDKJAVQE\nEwEIAD4WIQT4NAOiA59iibo96Owf1XMBhn8o2wUCWQs7PQIbAwUJA8JnAAULCQgH\nAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAf1XMBhn8o29bCB/9K9Kgi0ZRqHIbTxoyV\nLeZdunA/5BHKBMghnFB2pi2ij9fg+IY/KwVimG8WOR275OLe7+OtYLWrdmuW4Xn8\nueUTOhoNEt16N+2Pzj202QuI7o7q3eAaJbsMm0zueZURwemKlZPkxs2Qf7EQXZTL\nr6z7/aeCEeReRXTs9WxqUmPOgvZlGW9/aXmo4RPrn7FtXYzd+3Nvg9KM6gF06wBq\n1HimaaV+ADbbfFA5J4aF4DGnJnOBpWzRbCVpKqUcFEd9oA7mfCRMbp3bCzS4kVRH\nme7SyQh+L4Nqo1tqpWMWLyrwi5JwC9vF76alBZW2o0aObgBovW3FJj+bypqWPzQd\n7ceouQENBFkLOz0BCACxvET935QfIE2zm/mnNN9UUOF6FogP5K22WvfxjGzYFyhR\nuQvssTuXP/pwHmsW/X6sOBBQ3W/9HuZ34PwwR15PEtgoCmrwwkJTwYwbSZLXO655\nwU9hWiX07fQ+aagWbhWfuVPI02N3nBqoV0GW3EcVT9ZDYriVMiPJHXkNKTLqBngY\n4jAqiTLW9+nzXtxyYsiYtevo7v8g/fHggnJlgOVTMyJfS+aDMZbsmz0zpUqESVRn\nJ+Dt7xQJWdEKLe+OFPVeoyr5iDzpOS88XIFWL9PehBp4skEol6qeaSjE80xOIbfU\nQASjp5ltwF8idE40tLPGPTyBh1nlYHsDVl/LKkIhABEBAAGJATwEGAEIACYWIQT4\nNAOiA59iibo96Owf1XMBhn8o2wUCWQs7PQIbDAUJA8JnAAAKCRAf1XMBhn8o21k1\nB/9npFnxDQdQA9P+YPQ3/NLKPt+Hz9a7CQmXHhaUu4JY68j3ukCvK2EHt7/3jO3k\nm1SJz60qZs/mzfEVd9jq6B8QMk2NLQ/9at2TJ59VX7bkqoe9mEjzDSSoV+3GqGmX\nOYT8964psI+F1JnifXmp+wV1QxWxBQqZ//n6qzMH5upozaaMAvHIH+EzOTAYJZjQ\n9rde8OkJo/cHNCCmvSJ6jLkm8p3pPU31G5MWNgpTuuY+mABA6Qjns4+fQhfUZ/OQ\nxacM7Gb8v9ue/HS3fqKgrQKgzOWpUacBtCeeI4wJaytlsMfj4Ar21hkAcjbeCm+y\nG/Xai3YBcGKptD8FGd4MzDLV\n=BMOn\n-----END PGP PUBLIC KEY BLOCK-----\n"
	privkey2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n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\ncjbeCm+yG/Xai3YBcGKptD8FGd4MzDLV\n=FsP6\n-----END PGP PRIVATE KEY BLOCK-----\n"
)

func checkError(err error, t *testing.T) {
	if err != nil {
		t.Fail()
	}
}

func TestEncryptDecrypt(t *testing.T) {
	sender_keypair := &KeyPair{Pubkey: pubkey1, Privkey: privkey1}
	recepient_keypair := &KeyPair{Pubkey: pubkey2}
	recepient_keypair_with_privkey := &KeyPair{Pubkey: pubkey2, Privkey: privkey2}

	enc_msg, err := EncryptAndSign(message, recepient_keypair, sender_keypair)
	checkError(err, t)

	sig_ok, err := enc_msg.VerifySignature()
	checkError(err, t)
	if !sig_ok {
		t.Fail()
	}

	sig_ok, err = enc_msg.VerifySignatureAgainst(pubkey2)
	if sig_ok || err == nil {
		t.Fail()
	}

	decrypted, err := DecryptAndVerify(enc_msg, recepient_keypair_with_privkey)
	checkError(err, t)

	if decrypted.Text != message {
		t.Fail()
	}

	if !decrypted.SignatureOk {
		t.Fail()
	}

	_, err = GenerateKeyPair()
	checkError(err, t)
}
