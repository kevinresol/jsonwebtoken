package jsonwebtoken.signer;

import haxe.crypto.Hmac;
import jsonwebtoken.Signer;
import jsonwebtoken.Codec;
import jsonwebtoken.Crypto;

using jsonwebtoken.Algorithm;
using haxe.io.Bytes;
using haxe.Json;
using haxe.crypto.Base64;
using tink.CoreApi;
using StringTools;

class BasicSigner implements Signer {
	var algorithm:Algorithm;
	var crypto:Crypto;
	
	public function new(algorithm, crypto) {
		this.algorithm = algorithm;
		this.crypto = crypto;
	}
	
	public function sign<T:Claims>(claims:T):Promise<String> {
		var header = Codec.encodeSegment({
			alg: algorithm.toString(),
			typ: 'JWT',
		});
		
		var payload = Codec.encodeSegment(claims);
		var input = '$header.$payload';
		
		return crypto.sign(input, algorithm).next(function(sig) return '$input.$sig');
	}
}