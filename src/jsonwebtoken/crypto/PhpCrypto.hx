package jsonwebtoken.crypto;

import jsonwebtoken.Algorithm;
import jsonwebtoken.Codec;

using tink.CoreApi;

@:require(php)
class PhpCrypto implements Crypto {
	
	public function new() {}
	
	public function encode(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:String, key:String) {
			if(key == null) return Failure(new Error('Secret Missing'));
			var hmac = untyped __call__('hash_hmac', alg, input, key, true);
			return Success(Codec.sanitize(untyped __call__('base64_encode', hmac)));
		}
		
		function _sign(alg:String, keys:Keys) {
			if(keys.privateKey == null) return Failure(new Error('Private Key Missing'));
			var key = untyped __call__('openssl_pkey_get_private', keys.privateKey, keys.passcode);
			var signature = null;
			untyped __call__('openssl_sign', input, signature, key, alg);
			return Success(Codec.sanitize(untyped __call__('base64_encode', signature)));
		}
		
		return switch algorithm {
			case HS256(secret): _hmac('sha256', secret);
			case HS384(secret): _hmac('sha384', secret);
			case HS512(secret): _hmac('sha512', secret);
			case RS256(keys): _sign('SHA256', keys);
			case RS384(keys): _sign('SHA384', keys);
			case RS512(keys): _sign('SHA512', keys);
		}
	}
	
}