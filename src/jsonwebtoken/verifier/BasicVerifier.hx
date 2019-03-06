package jsonwebtoken.verifier;

import jsonwebtoken.Verifier;
import jsonwebtoken.Sequence;
import jsonwebtoken.Crypto;
import jsonwebtoken.crypto.DefaultCrypto;

using jsonwebtoken.Algorithm;
using jsonwebtoken.Codec;
using tink.CoreApi;

class BasicVerifier implements Verifier {
	
	var algorithm:Algorithm;
	var crypto:Crypto;
	var options:VerifyOptions;
	
	public function new(algorithm, ?crypto, ?options) {
		this.algorithm = algorithm;
		this.crypto = switch crypto {
			case null: new DefaultCrypto();
			case v: v;
		}
		this.options = options;
	}
	
	public function verify<T:Claims>(token:String):Promise<T> {
		if(token == null || token == '') return new Error('Token missing');
		
		switch token.sanitize().split('.') {
			case [h, p, s]:
				var header:Header = try Codec.decodeSegment(h) catch(e:Dynamic) return Error.withData('Invalid JWT header', e);
				
				// if(header.typ != 'JWT') return new Error('Invalid typ header');
				if(header.alg != algorithm.toString()) return new Error('Invalid algorithm');
				
				return crypto.verify('$h.$p', algorithm, s).next(function(sig):Outcome<T, Error> {
					var payload:Claims = try Codec.decodeSegment(p) catch(e:Dynamic) return Failure(Error.withData('Invalid JWT payload', e));
					
					if(payload.nbf != null && Std.is(payload.nbf, Float) && Date.now().getTime() / 1000 < payload.nbf.toInt())
						return Failure(new Error('Not available yet (nbf)'));
					
					if(payload.exp != null && Std.is(payload.exp, Float) && Date.now().getTime() / 1000 > payload.exp.toInt())
						return Failure(new Error('Expired (exp)'));
					
					if(options != null) {
						if(options.iss != null) {
							if(options.iss.indexOf(payload.iss) == -1)
								return Failure(new Error('Invalid issuer (iss)'));
						}
						if(options.aud != null) {
							var aud:Dynamic = payload.aud;
							if(Std.is(aud, String)) {
								if(options.aud != aud) 
									return Failure(new Error('Invalid audience (aud)'));
							} else {
								if((aud:Array<String>).indexOf(options.aud) == -1)
									return Failure(new Error('Invalid audience (aud)'));
							} 
						}
					}
					return Success(cast payload);
				});
				
			default:
				return new Error('Invalid token');
		}
	}
}

typedef VerifyOptions = {
	?aud:String,
	?iss:Sequence<String>,
}