package jsonwebtoken.crypto;

import jsonwebtoken.Algorithm;
import jsonwebtoken.Codec;

using tink.CoreApi;

/**
	On Windows:
	Enable openssl extension by uncommenting `extension=php_openssl.dll` in php.ini
**/
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
			case None: '';
			case HS256(secret): _hmac('SHA256', secret);
			case HS384(secret): _hmac('SHA384', secret);
			case HS512(secret): _hmac('SHA512', secret);
			case RS256(keys): _rsa('SHA256', keys);
			case RS384(keys): _rsa('SHA384', keys);
			case RS512(keys): _rsa('SHA512', keys);
		}
	}
	
	public function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise> {
		
		function _result(success)
			return success ? Success(Noise) : Failure(new Error('Invalid signature'));
		
		function _hmac()
			return sign(input, algorithm).next(function(sig) return _result(sig == signature));
		
		function _rsa(alg:String, keys:Keys) {
			if(keys.publicKey == null) return Failure(new Error('Public Key Missing'));
			var key = untyped __call__('openssl_pkey_get_public', keys.publicKey);
			var signature = untyped __call__('base64_decode', Codec.unsanitize(signature));
			return _result(untyped __call__('openssl_verify', input, signature, key, alg) == 1);
		}
			
		return switch algorithm {
			case None: _result(signature == '');
			case HS256(secret): _hmac();
			case HS384(secret): _hmac();
			case HS512(secret): _hmac();
			case RS256(keys): _rsa('SHA256', keys);
			case RS384(keys): _rsa('SHA384', keys);
			case RS512(keys): _rsa('SHA512', keys);
		}
	}
	
}