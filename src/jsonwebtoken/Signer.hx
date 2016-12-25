package jsonwebtoken;

using tink.CoreApi;

interface Signer {
	function sign<T:Claims>(claims:T):Promise<String>;
}

typedef Claims = {
	?iss:String,
	?sub:String,
	?aud:Sequence<String>,
	?exp:EpochTimeSeconds,
	?nbf:EpochTimeSeconds,
	?iat:EpochTimeSeconds,
	?jti:String,
}

abstract EpochTimeSeconds(Int) from Int to Int {
	@:from
	public static inline function fromDate(date:Date):EpochTimeSeconds
		return Std.int(date.getTime() / 1000);
}

@:forward(concat, copy, filter, indexOf, iterator, join, lastIndexOf, map, slice, toString)
abstract Sequence<T>(Array<T>) from Array<T> to Array<T> {
  @:from
  public static inline function ofSingle<T>(v:T):Sequence<T>
    return [v];
  
  @:arrayAccess
  public inline function get(i:Int)
    return this[i];
}