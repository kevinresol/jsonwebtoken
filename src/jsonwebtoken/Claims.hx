package jsonwebtoken;

import haxe.extern.EitherType;

typedef Claims = {
	?iss:String,
	?sub:String,
	?aud:EitherType<Array<String>, String>,
	?exp:EpochTimeSeconds,
	?nbf:EpochTimeSeconds,
	?iat:EpochTimeSeconds,
	?jti:String,
}

abstract EpochTimeSeconds(Int) to Int from Int {
	@:from
	public static inline function fromDate(date:Date):EpochTimeSeconds
		return Std.int(date.getTime() / 1000);
		
	@:to
	public inline function toDate():Date
		return Date.fromTime(this * 1000);
	
	@:to 
	public inline function toInt():Int
		return this;
}
