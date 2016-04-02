# jsonwebtoken ![travis](https://travis-ci.org/kevinresol/jsonwebtoken.svg?branch=master)
Haxe implementation of JsonWebToken


Tested Targets: 
- Neko
- Python
- (Node)JS
- Flash
- Java
- C++
- C# (Fails on Haxe 3.2.1. Passes on Haxe development)
- PHP (Fails if encoded object is an empty one (`{}`), see https://github.com/HaxeFoundation/haxe/issues/5015)

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