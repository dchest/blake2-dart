import 'dart:convert';
import 'package:crypto/crypto.dart';
import '../lib/blake2.dart';

main() {
  var h = new BLAKE2s();
  h.add(UTF8.encode("I want to hash this string"));
  var digest = h.close();
  print(CryptoUtils.bytesToHex(digest));
}

