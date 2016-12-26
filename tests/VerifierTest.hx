package;

import jsonwebtoken.Algorithm;
import jsonwebtoken.Claims;
import jsonwebtoken.verifier.*;
import jsonwebtoken.crypto.*;

import tink.unit.Assert.*;

using tink.CoreApi;

class VerifierTest {
	
	var secret:String;
	
	public function new() {
		secret = 'secret';
	}
	
	function isFailure<T:Claims>(msg:String, result:Surprise<T, Error>, ?pos:haxe.PosInfos)
		return result.map(function(o) return switch o {
			case Failure(e): equals(msg, e.message, pos);
			case Success(_): Failure(new Error('Expected Failure', pos));
		});
	
	public function testFailOnInvalidNumberOfSegments() {
		var verifier = getVerifier(HS256(secret));
		return isFailure('Invalid token', verifier.verify('abc'));
	}
	
	public function testFailOnEmptyStringToken(){
		var verifier = getVerifier(HS256(secret));
		return isFailure('Token missing', verifier.verify(''));
	}
	
	public function testFailOnNullStringToken(){
		var verifier = getVerifier(HS256(secret));
		return isFailure('Token missing', verifier.verify(null));
	}
	
	public function testFailOnInvalidSignature(){
		var secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
		var verifier = getVerifier(HS256(secret));
		var token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.suchsignature_plzvalidate_zomgtoken";
		return isFailure('Invalid signature', verifier.verify(token));
	}
	
	public function testVerifySignature(){
		var secret = haxe.crypto.Base64.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ+EstJQLr/T+1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
		var verifier = getVerifier(HS256(secret));
		var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0In0.7WTHQLacmw0-FudKlwqw-3U4ILeHkDsVqQ-RTIPm5SU";
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	public function testMatchedAlgorithm() {
		var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.4BjJWnO3nkNiYiR1ECGmMnsrLzpTm4l0zvYWpiPAtKw";
		var verifier = getVerifier(HS256('such secret'));
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	public function testFailOnUnmatchedAlgorithm() {
		var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.4BjJWnO3nkNiYiR1ECGmMnsrLzpTm4l0zvYWpiPAtKw";
		var verifier = getVerifier(HS384('such secret'));
		return isFailure('Invalid algorithm', verifier.verify(token));
	}
	
	public function testUnexpired() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIxNDc0ODM2NDd9.49EWHIcHjviJjyGuJ3DObkvgZd61JjbHMgRKjTtrABw';
		var verifier = getVerifier(HS256(secret));
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	public function testFailWhenExpired() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk0OTMzODA2MX0.zk_5pJ8NIxCas7ziMZHWEOh5ARcWc-PbxlAKzfKH0Wg';
		var verifier = getVerifier(HS256(secret));
		return isFailure('Expired (exp)', verifier.verify(token));
	}
	
	public function testFailIssuer() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIifQ.FgSmi1aRikqCuBD_FwCa6yla30DVc9AgnyF-HAII--U';
		var verifier = getVerifier(HS256(secret), {iss: 'issuer_'});
		return isFailure('Invalid issuer (iss)', verifier.verify(token));
	}
	
	public function testIssuer() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIifQ.FgSmi1aRikqCuBD_FwCa6yla30DVc9AgnyF-HAII--U';
		var verifier = getVerifier(HS256(secret), {iss: 'issuer'});
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	public function testIssuers() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIifQ.FgSmi1aRikqCuBD_FwCa6yla30DVc9AgnyF-HAII--U';
		var verifier = getVerifier(HS256(secret), {iss: ['issuers_', 'issuer']});
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	public function testFailAudience() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaSJdfQ.uRTaMJ0PDi61dkJ5ipM2HVeSPQlrOiddFP3np2E5k-M';
		var verifier = getVerifier(HS256(secret), {aud: 'audi_'});
		return isFailure('Invalid audience (aud)', verifier.verify(token));
	}
	
	public function testAudience() {
		var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaSJdfQ.uRTaMJ0PDi61dkJ5ipM2HVeSPQlrOiddFP3np2E5k-M';
		var verifier = getVerifier(HS256(secret), {aud: 'audi'});
		return verifier.verify(token).next(function(_) return Noise);
	}
	
	function getVerifier(alg:Algorithm, ?options) {
		return new BasicVerifier(alg, new StdCrypto(), options);
	}
}