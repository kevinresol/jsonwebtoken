package jsonwebtoken;

import haxe.io.Bytes;

enum Algorithm {
	HS256(secret:Secret);
	HS384(secret:Secret);
	HS512(secret:Secret);
	RS256(keys:Keys);
	RS384(keys:Keys);
	RS512(keys:Keys);
}

class AlgorithmTools {
	public static inline function toString(a:Algorithm)
		return a.getName();
}

@:forward
abstract Secret(String) from String to String {
	@:to
	public inline function toBytes():Bytes
		return Bytes.ofString(this);
}

typedef Keys = {
	publicKey:String,
	?privateKey:String,
	?passcode:String,
}