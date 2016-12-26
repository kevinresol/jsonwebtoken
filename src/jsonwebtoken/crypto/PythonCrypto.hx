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
	
	public function encode(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:Void->Hashlib, key:Secret) {
			var digest = Hmac.new_(key.getData(), {msg: Bytes.ofString(input).getData(), digestmod: alg}).digest();
			return Success(Base64.encode(Bytes.ofData(digest)).sanitize());
		}
		
		inline function unsupported()
			return Failure(new Error('Unsupported Algorithm'));
		
		return switch algorithm {
			case HS256(secret): _hmac(Hashlib.sha256, secret);
			case HS384(secret): _hmac(Hashlib.sha384, secret);
			case HS512(secret): _hmac(Hashlib.sha512, secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
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