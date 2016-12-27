package jsonwebtoken;

import haxe.io.Bytes;

enum Algorithm {
	None;
	HS256(secret:Secret);
	HS384(secret:Secret);
	HS512(secret:Secret);
	RS256(keys:Keys);
	RS384(keys:Keys);
	RS512(keys:Keys);
}

class AlgorithmTools {
	public static inline function toString(a:Algorithm)
		return switch a {
			case None: 'none';
			default: a.getName();
		}
}

@:forward
abstract Secret(Bytes) from Bytes to Bytes {
	@:from
	public static inline function fromString(v:String):Secret
		return Bytes.ofString(v);
		
	@:to
	public inline function toString():String
		return this.toString();
		
	#if nodejs
	@:to
	public inline function toBuffer():js.node.Buffer
		return js.node.Buffer.hxFromBytes(this);
	#end
}

typedef Keys = {
	publicKey:String,
	?privateKey:String,
	?passcode:String,
}