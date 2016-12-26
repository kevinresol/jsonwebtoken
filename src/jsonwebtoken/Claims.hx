package jsonwebtoken;

typedef Claims = {
	?iss:String,
	?sub:String,
	?aud:Sequence<String>,
	?exp:EpochTimeSeconds,
	?nbf:EpochTimeSeconds,
	?iat:EpochTimeSeconds,
	?jti:String,
}

abstract EpochTimeSeconds(Int) from Int {
	@:from
	public static inline function fromDate(date:Date):EpochTimeSeconds
		return Std.int(date.getTime() / 1000);
	
	@:to
	public inline function toInt():Int
		return this;
}
