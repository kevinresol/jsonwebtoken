package jsonwebtoken.crypto;

import haxe.crypto.Base64;
import haxe.io.Bytes;
import jsonwebtoken.Algorithm;
import cs.system.security.cryptography.HMAC;
import cs.system.security.cryptography.HMACSHA256;
import cs.system.security.cryptography.HMACSHA384;
import cs.system.security.cryptography.HMACSHA512;

using jsonwebtoken.Codec;
using tink.CoreApi;

@:require(cs)
class CsCrypto implements Crypto {
	
	public function new() {}
	
	inline function unsupported<T>():Outcome<T, Error>
		return Failure(new Error('Unsupported Algorithm'));
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(hmac:HMAC) {
			hmac.Initialize();
			var digest = hmac.ComputeHash(Bytes.ofString(input).getData());
			return Success(Base64.encode(Bytes.ofData(digest)).sanitize());
		}
		
		return switch algorithm {
			case HS256(secret): _hmac(new HMACSHA256(secret.getData()));
			case HS384(secret): _hmac(new HMACSHA384(secret.getData()));
			case HS512(secret): _hmac(new HMACSHA512(secret.getData()));
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
	public function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise> {
		
		function _result(success)
			return success ? Success(Noise) : Failure(new Error('Invalid signature'));
		
		function _hmac()
			return sign(input, algorithm).next(function(sig) return _result(sig == signature));
			
		return switch algorithm {
			case HS256(secret): _hmac();
			case HS384(secret): _hmac();
			case HS512(secret): _hmac();
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
}
