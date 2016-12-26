package jsonwebtoken.crypto;

import haxe.crypto.Md5;
import tink.io.IdealSource;
import jsonwebtoken.Algorithm;

#if asys
import asys.io.Process;
import asys.io.File;
import asys.FileSystem;
#elseif sys
import sys.io.Process;
import sys.io.File;
import sys.FileSystem;
#end

using jsonwebtoken.Codec;
using haxe.io.Bytes;
using haxe.crypto.Base64;
using StringTools;
using tink.CoreApi;

class OpensslCrypto implements Crypto {
	
	public function new() {}
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:String, key:String) {
			var proc = new Process('openssl', ['dgst', '-binary', '-$alg', '-hmac', key]);
			#if asys
				(input:IdealSource).pipeTo(proc.stdin, {end: true}).handle(function(_) {});
				return proc.stdout.all() >>
					function(bytes:Bytes) return Base64.encode(bytes).sanitize();
			#elseif sys
				proc.stdin.write(Bytes.ofString(input));
				proc.stdin.close();
				return Base64.encode(proc.stdout.readAll()).sanitize();
			#end
		}
		
		function _rsa(alg:String, keys:Keys) {
			var keyPath = '/tmp/' + Md5.encode(keys.privateKey) + '-' + Date.now().getTime() + '-' + Std.random(99999) + '.pem';
			var args = ['dgst', '-binary', '-$alg', '-sign', keyPath];
			if(keys.passcode != null) {
				args.push('-passin');
				args.push('pass:' + keys.passcode);
			}
			var proc = new Process('openssl', args);
			#if asys
				return File.saveContent(keyPath, keys.privateKey) >>
					function(o) {
						(input:IdealSource).pipeTo(proc.stdin, {end: true}).handle(function(_) {});
						return proc.stdout.all() >>
							function(bytes:Bytes) return FileSystem.deleteFile(keyPath) >>
							function(_) return Base64.encode(bytes).sanitize();
					}
			#elseif sys
				File.saveContent(keyPath, keys.privateKey);
				proc.stdin.write(Bytes.ofString(input));
				proc.stdin.close();
				var result = Base64.encode(proc.stdout.readAll()).sanitize();
				FileSystem.deleteFile(keyPath);
				return result;
			#end
		}
		
		return switch algorithm {
			case HS256(secret): _hmac('sha256', secret);
			case HS384(secret): _hmac('sha384', secret);
			case HS512(secret): _hmac('sha512', secret);
			case RS256(keys): _rsa('sha256', keys);
			case RS384(keys): _rsa('sha384', keys);
			case RS512(keys): _rsa('sha512', keys);
		}
	}
}