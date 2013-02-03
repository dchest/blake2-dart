// Written in 2013 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

import 'dart:crypto';
import '../lib/blake2.dart';

const MEBIBYTE = 1024*1024;

measure(name, fn) {
  var stopWatch = new Stopwatch()..start();
  var bytes = fn();
  var mebibytesPerSecond = (bytes/MEBIBYTE) / (stopWatch.elapsedMilliseconds/1000);
  print("${name} ${mebibytesPerSecond} MiB/s");
}

measureHash(name, hash) {
  var zeros = new List.fixedLength(128, fill: 0);
  measure(name, () {
    var zlen = zeros.length;
    var i;
    for (i = 0; i < 2*MEBIBYTE; i += zlen) {
      hash.add(zeros);
    }
    hash.close();
    return i;
  });
}

main() {
  print('Running...');
  measureHash('BLAKE-2s', new BLAKE2s());
  measureHash('SHA-256', new SHA256());
}