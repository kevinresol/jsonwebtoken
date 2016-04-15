# jsonwebtoken [![Build Status](https://travis-ci.org/kevinresol/jsonwebtoken.svg?branch=master)](https://travis-ci.org/kevinresol/jsonwebtoken)
Haxe implementation of JsonWebToken


##### Tested Targets:
- Neko
- Python
- (Node)JS
- Flash
- Java
- C++
- C# (Fails on Haxe 3.2.1. Passes on Haxe development)
- PHP (Fails if encoded object is an empty one (`{}`), see https://github.com/HaxeFoundation/haxe/issues/5015)
	
	
##### Algorithms


|Algorithm|Status|
|---|---|
|HS256|Supported|
|HS384|Not supported|
|HS512|Not supported|
|RS256|Not supported|
|RS384|Not supported|
|RS512|Not supported|


##### Supported Verifications

- Issuer
- Audience
- Expiry
	
# Install

```
haxelib install jsonwebtoken
```

# Usage

## Signing
```haxe
var jwt = new JsonWebToken('my secret');
var token = jwt.sign(payload);
```
Options: (TODO)

## Verifying

```haxe
var jwt = new JsonWebToken('my secret');
jwt.verify('some.jwt.string');
```

Options: (TODO)
