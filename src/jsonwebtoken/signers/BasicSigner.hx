package jsonwebtoken.signers;

import haxe.crypto.Hmac;
import jsonwebtoken.Signer;
import jsonwebtoken.Codec;

using jsonwebtoken.Algorithm;
using haxe.io.Bytes;
using haxe.Json;
using haxe.crypto.Base64;
using tink.CoreApi;
using StringTools;

class BasicSigner implements Signer {
	var algorithm:Algorithm;
	
	public function new(algorithm) {
		this.algorithm = algorithm;
	}
	
	public function sign<T:Claims>(claims:T):Promise<String> {
		var header = Codec.encodeSegment({
			alg: algorithm.toString(),
			typ: 'JWT',
		});
		
		var payload = Codec.encodeSegment(claims);
		var input = '$header.$payload';
		return switch encodeSignature(input, algorithm) {
			case Success(signature): '$input.$signature';
			case Failure(e): return e;
		}
	}
	
	function unsupported()
		return Failure(new Error('Unsupported Algorithm'));
		
	function encodeSignature(input:String, algorithm:Algorithm):Outcome<String, Error>
		return unsupported();
}