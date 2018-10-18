package jsonwebtoken.crypto;

import haxe.crypto.Hmac;

using jsonwebtoken.Codec;
using haxe.io.Bytes;
using haxe.crypto.Base64;
using StringTools;
using tink.CoreApi;

class StdCrypto implements Crypto {
	
	public function new() {}
	
	inline function unsupported<T>():Outcome<T, Error>
		return Failure(new Error('Unsupported Algorithm'));
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:HashMethod, key:Bytes)
			return hmac(input, alg, key);
		
		return switch algorithm {
			case None: '';
			case HS256(secret): _hmac(SHA256, secret);
			case HS384(secret): _hmac(SHA384, secret);
			case HS512(secret): _hmac(SHA512, secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
	public function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise> {
		
		function _result(success)
			return success ? Success(Noise) : Failure(new Error('Invalid signature'));
		
		function _hmac(alg:HashMethod, key:Bytes)
			return hmac(input, alg, key).flatMap(function(sig) return _result(sig == signature));
			
		return switch algorithm {
			case None: _result(signature == '');
			case HS256(secret): _hmac(SHA256, secret);
			case HS384(secret): _hmac(SHA384, secret);
			case HS512(secret): _hmac(SHA512, secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
	function hmac(input:String, alg, key)
		return Success(new Hmac(alg).make(key, input.ofString()).encode().toString().sanitize());
}