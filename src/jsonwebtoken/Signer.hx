package jsonwebtoken;

using tink.CoreApi;

interface Signer {
	function sign<T:Claims>(claims:T):Promise<String>;
}