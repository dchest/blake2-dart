import 'dart:crypto';
import 'dart:utf';
import '../lib/blake2.dart';

main() {
  var h = new BLAKE2s();
  h.add(encodeUtf8("I want to hash this string"));
  var digest = h.close();
  print(CryptoUtils.bytesToHex(digest));
}

