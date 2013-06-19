import 'dart:utf';
import 'package:crypto/crypto.dart';
import '../lib/blake2.dart';

main() {
  var h = new BLAKE2s();
  h.add(encodeUtf8("I want to hash this string"));
  var digest = h.close();
  print(CryptoUtils.bytesToHex(digest));
}

