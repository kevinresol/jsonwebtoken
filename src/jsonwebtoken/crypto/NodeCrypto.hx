package jsonwebtoken.crypto;

import jsonwebtoken.Algorithm;
import js.node.Crypto.*;
import js.node.Buffer;

using jsonwebtoken.Codec;
using tink.CoreApi;

@:require(nodejs)
class NodeCrypto implements Crypto {
	
	public function new() {}
	
	public function encode(input:String, algorithm:Algorithm):Promise<String> {
		function _hmac(alg:String, key:Buffer) {
			if(key == null) return Failure(new Error('Secret Missing'));
			var hmac = createHmac(alg, key);
			hmac.update(input);
			return Success(hmac.digest('base64').sanitize());
		}
		
		function _sign(alg:String, keys:Keys) {
			var sign = createSign(alg);
			sign.update(input);
			return Success(sign.sign(switch keys {
				case {privateKey: null}: return Failure(new Error('Private Key Missing'));
				case {privateKey: key, passcode: null}: key;
				case {privateKey: key, passcode: pass}: cast {key: key, passphrase: pass}; // FIXME: remove cast - https://github.com/HaxeFoundation/hxnodejs/pull/86
			}, 'base64').sanitize());
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