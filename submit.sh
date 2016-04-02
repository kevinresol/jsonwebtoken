#!/bin/sh

zip -r jsonwebtoken.zip haxelib.json src README.md
haxelib submit jsonwebtoken.zip
rm jsonwebtoken.zip