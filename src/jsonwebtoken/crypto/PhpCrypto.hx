package jsonwebtoken.crypto;

import jsonwebtoken.Algorithm;
import jsonwebtoken.Codec;

using tink.CoreApi;

@:require(php)
class PhpCrypto implements Crypto {
	
	public function new() {}
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:String, key:String) {
			if(key == null) return Failure(new Error('Secret Missing'));
			var hmac = untyped __call__('hash_hmac', alg, input, key, true);
			return Success(Codec.sanitize(untyped __call__('base64_encode', hmac)));
		}
		
		function _rsa(alg:String, keys:Keys) {
			if(keys.privateKey == null) return Failure(new Error('Private Key Missing'));
			var key = untyped __call__('openssl_pkey_get_private', keys.privateKey, keys.passcode);
			var signature = null;
			untyped __call__('openssl_sign', input, signature, key, alg);
			return Success(Codec.sanitize(untyped __call__('base64_encode', signature)));
		}
		
		return switch algorithm {
			case HS256(secret): _hmac('SHA256', secret);
			case HS384(secret): _hmac('SHA384', secret);
			case HS512(secret): _hmac('SHA512', secret);
			case RS256(keys): _rsa('SHA256', keys);
			case RS384(keys): _rsa('SHA384', keys);
			case RS512(keys): _rsa('SHA512', keys);
		}
	}
	
}