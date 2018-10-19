package jsonwebtoken.crypto;

import haxe.crypto.Md5;
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
using haxe.io.Path;
using haxe.crypto.Base64;
using StringTools;
using tink.CoreApi;
using tink.io.Source;
using tink.io.PipeResult;

#if nodejs @:require(asys) /* hxnodejs does not support sys.io.Process yet */ #end
class OpensslCrypto implements Crypto {
	
	public function new() {}
	
	public function sign(input:String, algorithm:Algorithm):Promise<String> {
		
		function _hmac(alg:String, key:Secret) {
			var proc = new Process('openssl', ['dgst', '-binary', '-$alg', '-mac', 'HMAC', '-macopt', 'hexkey:' + key.toHex()]);
			#if asys
				(input:IdealSource).pipeTo(proc.stdin, {end: true}).handle(function(_) {});
				return proc.stdout.all()
					.next(function(chunk) return Base64.encode(chunk).sanitize());
			#elseif sys
				proc.stdin.write(Bytes.ofString(input));
				proc.stdin.close();
				return Base64.encode(proc.stdout.readAll()).sanitize();
			#end
		}
		
		function _rsa(alg:String, keys:Keys) {
			if(keys.privateKey == null) return (new Error('Private Key Missing'):Promise<String>);
			var keyPath = '/tmp/' + Md5.encode(keys.privateKey) + '-' + Date.now().getTime() + '-' + Std.random(99999) + '.pem';
			var args = ['dgst', '-binary', '-$alg', '-sign', keyPath];
			if(keys.passcode != null) {
				args.push('-passin');
				args.push('pass:' + keys.passcode);
			}
			var proc = new Process('openssl', args);
			#if asys
				return File.saveContent(keyPath, keys.privateKey)
					.next(function(o) {
						return (input:IdealSource).pipeTo(proc.stdin, {end: true})
							.next(function(result) return result.toOutcome())
							.next(function(allWritten) return allWritten ? Noise : new Error('Failed writing to stdin of the openssl process'))
							.next(function(_) return proc.stdout.all())
							.next(function(chunk) return FileSystem.deleteFile(keyPath).swap(Base64.encode(chunk).sanitize()));
					});
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
			case None: '';
			case HS256(secret): _hmac('sha256', secret);
			case HS384(secret): _hmac('sha384', secret);
			case HS512(secret): _hmac('sha512', secret);
			case RS256(keys): _rsa('sha256', keys);
			case RS384(keys): _rsa('sha384', keys);
			case RS512(keys): _rsa('sha512', keys);
		}
	}
	
	public function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise> {
		
		function _result(success)
			return success ? Success(Noise) : Failure(new Error('Invalid signature'));
		
		function _hmac()
			return sign(input, algorithm).next(function(sig) return _result(sig == signature));
		
		function _rsa(alg:String, keys:Keys) {
			if(keys.publicKey == null) return (new Error('Public Key Missing'):Promise<Noise>);
			var tmpDir = getTmpDir().addTrailingSlash();
			var keyPath = tmpDir + Md5.encode(keys.publicKey) + '-' + Date.now().getTime() + '-' + Std.random(99999) + '.pem';
			var sigPath = tmpDir + Md5.encode(signature) + '-' + Date.now().getTime() + '-' + Std.random(99999) + '.sig';
			var args = ['dgst', '-$alg', '-verify', keyPath];
			var proc = new Process('openssl', ['dgst', '-$alg', '-verify', keyPath, '-signature', sigPath]);
			#if asys
				return Promise.inParallel([
					File.saveContent(keyPath, keys.publicKey),
					File.saveBytes(sigPath, Base64.decode(signature.unsanitize())),
				])
					.next(function(_) {
						return (input:IdealSource).pipeTo(proc.stdin, {end: true})
							.next(function(result) return result.toOutcome())
							.next(function(allWritten) return allWritten ? Noise : new Error('Failed writing to stdin of the openssl process'))
							.next(function(_) return proc.exitCode())
							.next(function(code) return Promise.inParallel([
								FileSystem.deleteFile(keyPath),
								FileSystem.deleteFile(sigPath),
							]).swap(_result(code == 0)));
					});
			#elseif sys
				File.saveContent(keyPath, keys.publicKey);
				File.saveBytes(sigPath, Base64.decode(signature.unsanitize()));
				proc.stdin.write(Bytes.ofString(input));
				proc.stdin.close();
				var code = proc.exitCode();
				FileSystem.deleteFile(keyPath);
				FileSystem.deleteFile(sigPath);
				return _result(code == 0);
			#end
		}
			
		return switch algorithm {
			case None: _result(signature == '');
			case HS256(secret): _hmac();
			case HS384(secret): _hmac();
			case HS512(secret): _hmac();
			case RS256(keys): _rsa('sha256', keys);
			case RS384(keys): _rsa('sha384', keys);
			case RS512(keys): _rsa('sha512', keys);
		}
	}
	
	inline function getTmpDir():String {
		return
			#if nodejs
				js.node.Os.tmpdir();
			#elseif php
				untyped __call__('sys_get_temp_dir');
			#elseif cs
				cs.system.io.Path.GetTempPath();
			#else
				switch Sys.systemName() {
					case 'Windows':
						switch Sys.getEnv('Temp') {
							case null: 'C:\\Temp';
							case v: v;
						}
					default: 
						switch Sys.getEnv('TMPDIR') {
							case null: '/tmp';
							case v: v;
						}
				}
			#end
	}
}