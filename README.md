# jsonwebtoken [![Build Status](https://travis-ci.org/kevinresol/jsonwebtoken.svg?branch=master)](https://travis-ci.org/kevinresol/jsonwebtoken)

Use JsonWebToken in Haxe
	
##### Supported Algorithms


| Target | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | Remarks|
| --- | :---: | :---: | :---: | :---: | :---: | :---: | --- | 
| all sys targets | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Using openssl cli |
| Node | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Using Node std lib |
| PHP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Using PHP std lib |
| Java | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | Using Java std lib |
| C# | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | Using C# std lib |
| Python | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | Using Python std lib |
| Interp | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Using Haxe std lib |
| Neko | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Using Haxe std lib |
| JS | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Using Haxe std lib |
| C++ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Using Haxe std lib |


##### Supported Verifications

- Issuer
- Audience
- Expiry
	
# Install

```
haxelib install jsonwebtoken
```

## Usage

### Signing

```haxe
var crypto = new NodeCrypto(); // pick a crypto from the jsonwebtoken.crypto package
var signer = new BasicSigner(HS256('secret'), crypto);
var payload:Claims = {iss: 'issuer'}
signer.sign(payload).handle(function(o) switch o {
	case Success(token): trace(token);
	case Failure(e): trace('Failed to sign: $e');
});
```


### Verifying

```haxe
var crypto = new NodeCrypto(); // pick a crypto from the jsonwebtoken.crypto package
var verifier = new BasicVerifier(HS256('secret'), crypto, {iss: 'issuer'});
var token = ...;
verifier.verify(token).handle(function(o) switch o {
	case Success(_): trace('verified');
	case Failure(e): trace('Invalid token: $e');
});
```
