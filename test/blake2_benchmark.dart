// Written in 2013 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

import "dart:crypto";
import "../lib/blake2s.dart";

final MEGABYTE = 1024*1024;

measure(name, fn) {
  var stopWatch = new Stopwatch()..start();
  var bytes = fn();
  print("${name} ${stopWatch.elapsedMilliseconds/1000}s per ${bytes/MEGABYTE} MB");
}

main() {
  print("Running...");

  var zeroes = [];
  zeroes.insertRange(0, 1*MEGABYTE, 0);

  measure("BLAKE-2s", () {
    var blake = new BLAKE2s();
    blake.add(zeroes);
    blake.close();
    return zeroes.length;
  });

  measure("SHA-256", () {
    var sha = new SHA256();
    sha.add(zeroes);
    sha.close();
    return zeroes.length;
  });
}