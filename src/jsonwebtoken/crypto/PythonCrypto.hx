package jsonwebtoken.crypto;

import haxe.crypto.Base64;
import haxe.io.Bytes;
import jsonwebtoken.Algorithm;
import python.Bytearray;
import python.KwArgs;

using jsonwebtoken.Codec;
using tink.CoreApi;

@:require(python)
class PythonCrypto implements Crypto {
	
	public function new() {}
	
	inline function unsupported<T>():Outcome<T, Error>
		return Failure(new Error('Unsupported Algorithm'));
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:Void->Hashlib, key:Secret)
			return hmac(input, alg, key);
		
		return switch algorithm {
			case None: '';
			case HS256(secret): _hmac(Hashlib.sha256, secret);
			case HS384(secret): _hmac(Hashlib.sha384, secret);
			case HS512(secret): _hmac(Hashlib.sha512, secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
	public function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise> {
		
		function _result(success)
			return success ? Success(Noise) : Failure(new Error('Invalid signature'));
		
		function _hmac(alg:Void->Hashlib, key:Secret)
			return hmac(input, alg, key).flatMap(function(sig) return _result(sig == signature));
			
		return switch algorithm {
			case None: _result(signature == '');
			case HS256(secret): _hmac(Hashlib.sha256, secret);
			case HS384(secret): _hmac(Hashlib.sha384, secret);
			case HS512(secret): _hmac(Hashlib.sha512, secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
	function hmac(input:String, alg:Void->Hashlib, key:Secret) {
		var digest = Hmac.new_(key.getData(), {msg: Bytes.ofString(input).getData(), digestmod: alg}).digest();
		return Success(Base64.encode(Bytes.ofData(digest)).sanitize());
	}
}

@:pythonImport('hashlib')
extern class Hashlib {
	static function sha256():Hashlib;
	static function sha384():Hashlib;
	static function sha512():Hashlib;
}

@:pythonImport('hmac')
extern class Hmac {
	@:native('new') static function new_(key:Bytearray, ?options:KwArgs<{?msg:Bytearray, ?digestmod:Void->Hashlib}>):Hmac;
	function digest():Bytearray;
}