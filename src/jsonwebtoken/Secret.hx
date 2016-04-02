package jsonwebtoken;

import haxe.io.Bytes;

@:forward
abstract Secret(Bytes) from Bytes to Bytes
{
	@:from
	public static inline function fromString(v:String):Secret return Bytes.ofString(v);
}