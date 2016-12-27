package;

import jsonwebtoken.Algorithm;
import jsonwebtoken.signer.*;
import jsonwebtoken.crypto.*;
import tink.unit.Assert.*;

class SignerTest {
	
	static var PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA33TqqLR3eeUmDtHS89qF
3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA
04DDnEFGAf+kDQiNSe2ZtqC7bnIc8+KSG/qOGQIVaay4Ucr6ovDkykO5Hxn7OU7s
Jp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwF
wnxCsU5+UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUE
f0YN3/Q0auBkdbDR/ES2PbgKTJdkjc/rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1W
SwIDAQAB
-----END PUBLIC KEY-----
';

	static var PASSCODE = 'passwd';
	static var PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,2E65118E6C7B5207

7cYUTW4ZBdmVZ4ILB08hcTdm5ib0E0zcy+I7pHpNQfJHtI7BJ4omys5S19ufJPBJ
IzYjeO7oTVqI37F6EUmjZqG4WVE2UQbQDkosZbZN82O4Ipu1lFAPEbwjqePMKufz
snSQHKfnbyyDPEVNlJbs19NXC8v6g+pQay5rH/I6N2iBxgsTmuemZ54EhNQMZyEN
R/CiheArWEH9H8/4hd2gc9Tb2s0MwGHILL4kbbNm5tp3xw4ik7OYWNrj3m+nG6Xb
vKXh2xEanAZAyMXTqDJTHdn7/CEqusQPJjZGV+Mf1kjKu7p4qcXFnIXP5ILnTW7b
lHoWC4eweDzKOMRzXmbABEVSUvx2SmPl4TcoC5L1SCAHEmZaKbaY7S5l53u6gl0f
ULuQbt7Hr3THznlNFKkGT1/yVNt2QOm1emZd55LaNe8E7XsNSlhl0grYQ+Ue8Jba
x85OapltVjxM9wVCwbgFyi04ihdKHo9e+uYKeTGKv0hU5O7HEH1ev6t/s2u/UG6h
TqEsYrVp0CMHpt5uAF6nZyK6GZ/CHTxh/rz1hADMofem59+e6tVtjnPGA3EjnJT8
BMOw/D2QIDxjxj2GUzz+YJp50ENhWrL9oSDkG2nzv4NVL77QIy+T/2/f4PgokUDO
QJjIfxPWE40cHGHpnQtZvEPoxP0H3T0YhmEVwuJxX3uaWOY/8Fa1c7Ln0SwWdfV5
gYvJV8o6c3sumcq1O3agPDlHC5O4IxG7AZQ8CHRDyASogzfkY6P579ZOGYaO4al7
WA1YIpsHs3/1f4SByMuWe0NVkFfvXckjpqGrBQpTmqQzk6baa0VQ0cwU3XlkwHac
WB/fQ4jylwFzZDcp5JAo53n6aU72zgNvDlGTNKwdXXZI5U3JPocH0AiZgFFWYJLd
63PJLDnjyE3i6XMVlxifXKkXVv0RYSz+ByS7Oz9aCgnQhNU8ycv+UxtfkPQih5zE
/0Y2EEFknajmFJpNXczzF8OEzaswmR0AOjcCiklZKRf61rf5faJxJhhqKEEBJuL6
oodDVRk3OGU1yQSBazT8nK3V+e6FMo3tWkra2BXFCD+pKxTy014Cp59S1w6F1Fjt
WX7eMWSLWfQ56j2kLMBHq5gb2arqlqH3fsYOTD3TNjCYF3Sgx309kVPuOK5vw61P
pnL/LN3iGY42WR+9lfAyNN2qj9zvwKwscyYs5+DPQoPmcPcVGc3v/u66bLcOGbEU
OlGa/6gdD4GCp5E4fP/7GbnEY/PW2abquFhGB+pVdl3/4+1U/8kItlfWNZoG4FhE
gjMd7glmrdFiNJFFpf5ks1lVXGqJ4mZxqtEZrxUEwciZjm4V27a+E2KyV9NnksZ6
xF4tGPKIPsvNTV5o8ZqjiacxgbYmr2ywqDXKCgpU/RWSh1sLapqSQqbH/w0MquUj
VhVX0RMYH/foKtjagZf/KO1/mnCITl86treIdachGgR4wr/qqMjrpPUaPLCRY3JQ
00XUP1Mu6YPE0SnMYAVxZheqKHly3a1pg4Xp7YWlM671oUORs3+VENfnbIxgr+2D
TiJT9PxwpfK53Oh7RBSWHJZRuAdLUXE8DG+bl0N/QkJM6pFUxTI1AQ==
-----END RSA PRIVATE KEY-----
';
	
	var secret:String;
	var keys:Keys;
	
	public function new() {
		secret = 'secret';
		keys = {
			publicKey: PUBLIC_KEY,
			privateKey: PRIVATE_KEY,
			passcode: PASSCODE,
		}
	}
	
	public function testHS256() {
		var signer = getSigner(HS256(secret));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.nVrY_yb-LcNKckLaXItppW57KQGiKXTEZVLqhptT6Do', token));
	}	
	
	public function testHS384() {
		var signer = getSigner(HS384(secret));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.X9DaLysdsHc-zZJNEffbWd2HRrWmX3qDKToWGGIJc_0s2SIbQJdHDV804m8LDLSW', token));
	}	
	
	public function testHS512() {
		var signer = getSigner(HS512(secret));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.ltlcf72E1-V-u2qGJ7MRiUBngFzp5vXrmC6wuKiQac8l6bcfVspLOnW_pCl-h5QiBp2ckxz51BAZKM8HQZ_-6Q', token));
	}	
	
	public function testRS256() {
		var signer = getSigner(RS256(keys));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.TehmtMaG975_ygPam2o1frZHkXBnLGNpZjJzAMiSu9IpDYVIFs9eRQmKWBEfPTWNL0VV6RhU2OYRsB8UZ-JUyddkiyTpVMcJ6V5ktLW5IeXtNp74-5FTeNIQYUvoSuoaJTs0wJ93PNxPvsfKUFdP80Slx4MTMXypi0ChxOQQmZ6vBKqJFx7kbdA_zlwVMfOPcYiPEBXciYVZXE6QHCz5zo-t9vQTTzZOpVz2o_fqaL0crWaZaKnMDWtCqQOHHPb7-Ir7GWBqOvmkaePiRXRCGTbeY2ISjsWERA2qaugrbKWJYFINUm62wtdmXubUiN9OeC9iirgZQGoewtuaxLM_KA', token));
	}	
	
	public function testRS384() {
		var signer = getSigner(RS384(keys));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.djXH4r4en_PkmlBB3qV9kLTsArbQkrnY4eU0QG7e61Uy_xFbiJceNfVnj9VDjJsTRoa9JoT13gVgEAkREn98rqX9KLEQhTHDGxwrFp8zQpM3LGQAV4LB4ZQmXBfd0QNmlpjqFEmM-mBAl8tkmqhQ7bxLH1Kmo4O9c1p0ZMZueUnwumWe-z5E66tzK-NaF9y8YKIFIetsVrcka918lsON5e2yDxIc8HOH3-1yPeDcMf5-fptWa_Ti5WgVnjIflDulXVv672czqX4PZ3IwJU8NbHPFG22KB5v620CbbtvGflvq8-lgNL_qwFwJ49AZA9kvDXVoB4xBmMmcPOTPrrghBA', token));
	}	
	
	public function testRS512() {
		var signer = getSigner(RS512(keys));
		return signer.sign(cast {iss: 'iss'})
			.next(function(token:String) return equals('eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MifQ.afuqwd1UtSdSy8qGoCz5bmsAxbWpywfnf8n_FcrmrvP2caw2ZzpyBrTEGlzFS3Jl5LAAKho_RjPycZjHWfKN_lsGzBlmdLb8nGSER1nnlAV9sXt1XBky0dIEhAYbUEb5lAz2kXHKnt3uy_RgweV1jBOHWwNbf8i_-wy31MwFabYzLEj4tuALOI3jHsJ3-mZBFpeHnQRSSKVtOoiAddz4QHLIRTRcYMwBxAGvgFacaXIt9T-lbp-OHye9j6Lagz5JlbEoEDlsdVYOy0J44xNtwabdmRUJgadyacvHQfesg55algX4t5go_jyyDoEHECXr5veHXcbcRVFEkdgt1eKLqg', token));
	}
	
	function getSigner(alg:Algorithm) {
		var crypto =
			#if openssl
				new OpensslCrypto()
			#elseif nodejs
				new NodeCrypto()
			#elseif php
				new PhpCrypto()
			#elseif java
				new JavaCrypto()
			#elseif python
				new PythonCrypto()
			#elseif cs
				new CsCrypto()
			#else
				new StdCrypto()
			#end ;
		return new BasicSigner(alg, crypto);
	}
}