package jsonwebtoken.signers;

import jsonwebtoken.Algorithm;
import js.node.Crypto;

using StringTools;
using tink.CoreApi;

@:require(nodejs)
class NodeSigner extends BasicSigner {
	override function encodeSignature(input:String, algorithm:Algorithm):Outcome<String, Error> {
		
		function _hmac(alg:String, key:String) {
			if(key == null) return Failure(new Error('Secret Missing'));
			var hmac = Crypto.createHmac(alg, key);
			hmac.update(input);
			return Success(hmac.digest('base64').replace('+', '-').replace('/', '_').replace('=', ''));
		}
		
		function _sign(alg:String, keys:Keys) {
			var sign = Crypto.createSign(alg);
			sign.update(input);
			return Success(sign.sign(switch keys {
				case {privateKey: null}: return Failure(new Error('Private Key Missing'));
				case {privateKey: key, passcode: null}: key;
				case {privateKey: key, passcode: pass}: cast {key: key, passphrase: pass}; // FIXME: remove cast - https://github.com/HaxeFoundation/hxnodejs/pull/86
			}, 'base64').replace('+', '-').replace('/', '_').replace('=', ''));
		}
		
		return switch algorithm {
			case HS256(secret): _hmac('sha256', secret);
			case HS384(secret): _hmac('sha384', secret);
			case HS512(secret): _hmac('sha512', secret);
			case RS256(keys): _sign('RSA-SHA256', keys);
			case RS384(keys): _sign('RSA-SHA384', keys);
			case RS512(keys): _sign('RSA-SHA512', keys);
		}
	}
}