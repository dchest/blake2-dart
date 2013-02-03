// Written in 2013 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

import 'dart:crypto';
import '../lib/blake2s.dart';

final MEGABYTE = 1024*1024;

measure(name, fn) {
  var stopWatch = new Stopwatch()..start();
  var bytes = fn();
  var megabytesPerSecond = (bytes/MEGABYTE) / (stopWatch.elapsedMilliseconds/1000);
  print("${name} ${megabytesPerSecond} MB/s");
}

measureHash(name, hash) {
  var zeros = new List.fixedLength(128, fill: 0);
  measure("BLAKE-2s", () {
    var zlen = zeros.length;
    var i;
    for (i = 0; i < 2*MEGABYTE; i += zlen) {
      hash.add(zeros);
    }
    hash.close();
    return i;
  });
}

main() {
  print("Running...");
  measureHash("BLAKE-2s", new BLAKE2s());
  measureHash("SHA-256", new SHA256());
}