package jsonwebtoken.signers;

import haxe.crypto.Hmac;

using haxe.io.Bytes;
using haxe.crypto.Base64;
using StringTools;
using tink.CoreApi;

class StdSigner extends BasicSigner {
	override function encodeSignature(input:String, algorithm:Algorithm):Outcome<String, Error> {
		return switch algorithm {
			case HS256(secret):
				var hmac = new Hmac(SHA256);
				Success(hmac.make(secret, input.ofString()).encode(false).toString().replace('+', '-').replace('/', '_').replace('=', ''));
			case HS384(secret):
				return unsupported();
			case HS512(secret):
				return unsupported();
			case RS256(keys):
				return unsupported();
			case RS384(keys):
				return unsupported();
			case RS512(keys):
				return unsupported();
		}
	}
}