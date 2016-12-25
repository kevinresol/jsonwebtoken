package jsonwebtoken;

using tink.CoreApi;

interface Verifier {
	function verify<T:Claims>(token:String):Promise<T>;
}