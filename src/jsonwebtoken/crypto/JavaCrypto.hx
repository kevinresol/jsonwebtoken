package jsonwebtoken.crypto;

import haxe.crypto.Base64;
import haxe.io.Bytes;
import jsonwebtoken.Algorithm;
import java.NativeArray;
import java.StdTypes.Int8;
import java.security.Signature;
import java.security.KeyPairGenerator;

using jsonwebtoken.Codec;
using tink.CoreApi;

@:require(java)
class JavaCrypto implements Crypto {
	
	public function new() {}
	
	public function encode(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:String, key:Secret) {
			return try {
				var signingKey = new SecretKeySpec(key.getData(), alg);
				var mac = Mac.getInstance(alg);
				mac.init(signingKey);
				var hmac = Bytes.ofData(mac.doFinal(Bytes.ofString(input).getData()));
				Success(Base64.encode(hmac).toString().sanitize());
			} catch(e:Dynamic) {
				Failure(Error.withData('Native error', e));
			}
		}
		
		inline function unsupported()
			return Failure(new Error('Unsupported Algorithm'));
		
		return switch algorithm {
			case HS256(secret): _hmac('HmacSHA256', secret);
			case HS384(secret): _hmac('HmacSHA384', secret);
			case HS512(secret): _hmac('HmacSHA512', secret);
			case RS256(keys): unsupported();
			case RS384(keys): unsupported();
			case RS512(keys): unsupported();
		}
	}
	
}

@:native('javax.crypto.Mac')
extern class Mac {
	static function getInstance(alg:String):Mac;
	function init(key:SecretKeySpec):Void;
	function doFinal(data:NativeArray<Int8>):NativeArray<Int8>;
}

@:native('javax.crypto.spec.SecretKeySpec')
extern class SecretKeySpec {
	function new(bytes:NativeArray<Int8>, alg:String);
}