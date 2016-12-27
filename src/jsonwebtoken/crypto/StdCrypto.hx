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
		
		return switch algorithm {
			case None: '';
			case HS256(secret):
				var hmac = new Hmac(SHA256);
				Success(hmac.make(secret, input.ofString()).encode().toString().sanitize());
			case HS384(secret): unsupported();
			case HS512(secret): unsupported();
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
			case None: _result(signature == '');
			case HS256(secret): _hmac();
			case HS384(secret): _hmac();
			case HS512(secret): _hmac();
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
}