package jsonwebtoken.signer;

import jsonwebtoken.Signer;
import jsonwebtoken.Codec;
import jsonwebtoken.Crypto;
import jsonwebtoken.crypto.DefaultCrypto;

using jsonwebtoken.Algorithm;
using haxe.io.Bytes;
using haxe.Json;
using haxe.crypto.Base64;
using tink.CoreApi;
using StringTools;

class BasicSigner implements Signer {
	var algorithm:Algorithm;
	var crypto:Crypto;
	
	public function new(algorithm, ?crypto) {
		this.algorithm = algorithm;
		this.crypto = switch crypto {
			case null: new DefaultCrypto();
			case v: v;
		}
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