package jsonwebtoken.crypto;

import haxe.crypto.Hmac;

using jsonwebtoken.Codec;
using haxe.io.Bytes;
using haxe.crypto.Base64;
using StringTools;
using tink.CoreApi;

class StdCrypto implements Crypto {
	
	public function new() {}
	
	public function encode(input:String, algorithm:Algorithm):Promise<String> {
		
		inline function unsupported()
			return Failure(new Error('Unsupported Algorithm'));
		
		return switch algorithm {
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
}