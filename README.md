# EasyPGP
<a href="https://godoc.org/github.com/EncryptedTimeline/EasyPGP"><img src="https://godoc.org/github.com/encryptedtimeline/easypgp?status.svg"></a>

PGP library for iOS available through gomobile

To use EasyPGP you would need to install gomobile tools, following [tutorial](https://github.com/golang/go/wiki/Mobile).
You also need to patch gomobile to support `Uint64`:
```patch
diff --git a/bind/gen.go b/bind/gen.go
index 546c5cf4..0428230f 100644
--- a/bind/gen.go
+++ b/bind/gen.go
@@ -232,7 +232,9 @@ func (g *Generator) cgoType(t types.Type) string {
 			return "int64_t"
 		case types.Uint8: // types.Byte
 			return "uint8_t"
-		// TODO(crawshaw): case types.Uint, types.Uint16, types.Uint32, types.Uint64:
+		// TODO(crawshaw): case types.Uint, types.Uint16, types.Uint32:
+		case types.Uint64:
+			return "uint64_t"
 		case types.Float32:
 			return "float"
 		case types.Float64, types.UntypedFloat:
```


After that you can build `EasyPGP.framework`:

```
go get github.com/encryptedtimeline/easypgp
gomobile bind -target=ios -o EasyPGP.framework  github.com/encryptedtimeline/easypgp
```

After adding `EasyPGP.framework` to your project you can straight-forward use it.

Swift example:

```swift
let pubkey1  = "-----BEGIN PGP PUBLIC KEY BLOCK-----...."
let privkey1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----...."
let pubkey2  = "-----BEGIN PGP PUBLIC KEY BLOCK-----...."
let privkey2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----...."


let sender = EasypgpNewKeyPairWithKeys(pubkey1, privkey1)
let receiver = EasypgpNewKeyPairWithKeys(pubkey2, nil)
let receiver_with_privkey = EasypgpNewKeyPairWithKeys(pubkey2, privkey2)


let msg = EasypgpEncryptAndSign("hello, world!", receiver, sender, nil)
NSLog((msg?.cipher())!)

let decrypted = EasypgpDecryptAndVerify(msg, receiver_with_privkey, nil)
NSLog((decrypted?.text())!)
```
