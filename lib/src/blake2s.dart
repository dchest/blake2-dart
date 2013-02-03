// Written in 2013 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

part of blake2;

class BLAKE2s implements Hash {

  const blockSize = 64;

  const int _blockSizeInWords = 16;

  const _MASK_8 = 0xff;
  const _MASK_32 = 0xffffffff;
  const _BYTES_PER_WORD = 4;
  const _ROUNDS = 10;

  // Hash state.
  List<int> _h; // chain
  List<int> _t; // counter
  List<int> _f; // finalization flags

  List<int> _pendingData; // pending bytes
  List<int> _currentBlockWords; // block words
  List<int> _v; // temporary space for compression.

  bool _digestCalled = false;

  // Parameters.
  int _digestLength;
  HashTreeConfig _tree;
  List<int> _key;
  List<int> _salt;
  List<int> _person;

  int get digestLength => _digestLength;

  static final List<List<int>> _SIGMA = const [
      const [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
      const [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
      const [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
      const [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
      const [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
      const [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
      const [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
      const [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
      const [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
      const [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
      const [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
      const [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
      const [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
      const [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ]
  ];

  static final List<int> _IV = const [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  // Helper methods.
  _rotr32(x, n) => (x >> n) | ((x << (32 - n)) & _MASK_32);
  _add32(x, y) => (x + y) & _MASK_32;

  /**
   *  Construct BLAKE2s hasher object, calculating hash of size [digestLength].
   */
  BLAKE2s({int digestLength : 32, List<int> key : null, List<int> salt : null,
    List<int> person : null, HashTreeConfig tree : null}) {
    _digestLength = digestLength;
    _key = key;
    _salt = salt;
    _person = person;
    _tree = tree;
    _initialize();
  }

  _initialize() {
    // Initialize state.
    _h = _IV.getRange(0, _IV.length);
    _t = [0, 0];
    _f = [0, 0];
    _v = new List.fixedLength(_blockSizeInWords);
    _currentBlockWords = new List.fixedLength(_blockSizeInWords);
    _pendingData = [];

    if (_digestLength < 1 || _digestLength > 32) {
      throw new HashException('Wrong digest length');
    }

    var keyLength = _key == null ? 0 : _key.length;
    if (keyLength > 32) {
      throw new HashException('Wrong key length');
    }

    var saltLength = _salt == null ? 0 : _salt.length;
    if (saltLength > 0 && saltLength != 8) {
      throw new HashException('Wrong salt length');
    }

    var personLength = _person == null ? 0 : _person.length;
    if (personLength > 0 && personLength != 8) {
      throw new HashException('Wrong personalization length');
    }

    // Create parameter block.
    var parameterBlock = new List.fixedLength(_h.length * _BYTES_PER_WORD,
                                              fill: 0);
    parameterBlock[0] = digestLength;
    parameterBlock[1] = keyLength;
    if (_salt != null) {
      parameterBlock.setRange(16, 8, _salt, 0);
    }
    if (_person != null) {
      parameterBlock.setRange(24, 8, _person, 0);
    }
    if (_tree != null) {
      parameterBlock[2] = _tree.fanout;
      parameterBlock[3] = _tree.maxDepth;

      parameterBlock[4] = (_tree.leafSize >> 0) & _MASK_8;
      parameterBlock[5] = (_tree.leafSize >> 8) & _MASK_8;
      parameterBlock[6] = (_tree.leafSize >> 16) & _MASK_8;
      parameterBlock[7] = (_tree.leafSize >> 24) & _MASK_8;

      parameterBlock[8] = (_tree.nodeOffset >> 0) & _MASK_8;
      parameterBlock[9] = (_tree.nodeOffset >> 8) & _MASK_8;
      parameterBlock[10] = (_tree.nodeOffset >> 16) & _MASK_8;
      parameterBlock[11] = (_tree.nodeOffset >> 24) & _MASK_8;
      parameterBlock[12] = (_tree.nodeOffset >> 32) & _MASK_8;
      parameterBlock[13] = (_tree.nodeOffset >> 40) & _MASK_8;

      parameterBlock[14] = _tree.nodeDepth;
      parameterBlock[15] = _tree.innerHashSize;
    } else {
      parameterBlock[2] = 1;
      parameterBlock[3] = 1;
    }

    // XOR parameter block into initial chain value.
    var paramWords = new List.fixedLength(_h.length, fill: 0);
    _bytesToWords(parameterBlock, 0, paramWords,_h.length);

    for (int i = 0; i < _h.length; i++) {
      _h[i] ^= paramWords[i];
    }

    if (_key != null) {
      // Process key.
      var _paddedKey = new List.fixedLength(blockSize, fill: 0);
      _paddedKey.setRange(0, keyLength, _key, 0);
      add(_paddedKey);
    }
  }

  BLAKE2s newInstance() {
    return new BLAKE2s(
        digestLength : _digestLength,
        key  : _key,
        salt : _salt,
        person : _person,
        tree : _tree
    );
  }

  BLAKE2s add(List<int> data) {
    if (_digestCalled) {
      throw new HashException('Hash add method called after close');
    }
    _pendingData.addAll(data);
    _iterate();
    return this;
  }

  _compressBlock() {
    // Copy state.
    _v.setRange(0, 8, _h);
    // Copy constants.
    _v.setRange(8, 8, _IV);
    // XOR counter.
    _v[12] ^= _t[0];
    _v[13] ^= _t[1];
    // XOR finalization flags.
    _v[14] ^= _f[0];
    _v[15] ^= _f[1];

    // Rounds.
    for (var round = 0; round < _ROUNDS; round++) {
      _G(round, 0, 4,  8, 12,  0);
      _G(round, 1, 5,  9, 13,  2);
      _G(round, 2, 6, 10, 14,  4);
      _G(round, 3, 7, 11, 15,  6);
      _G(round, 3, 4,  9, 14, 14);
      _G(round, 2, 7,  8, 13, 12);
      _G(round, 0, 5, 10, 15,  8);
      _G(round, 1, 6, 11, 12, 10);
    }

    // Feedforward.
    for (var i = 0; i < 16; i++) {
      _h[i % 8] ^= _v[i];
    }
  }

  _G(r, a, b, c, d, e) {
    _v[a] = _add32(_v[a], _add32(_currentBlockWords[_SIGMA[r][e]], _v[b]));
    _v[d] = _rotr32(_v[d] ^ _v[a], 16);
    _v[c] = _add32(_v[c], _v[d]);
    _v[b] = _rotr32(_v[b] ^ _v[c], 12);
    _v[a] = _add32(_v[a], _add32(_currentBlockWords[_SIGMA[r][e+1]], _v[b]));
    _v[d] = _rotr32(_v[d] ^ _v[a], 8);
    _v[c] = _add32(_v[c], _v[d]);
    _v[b] = _rotr32(_v[b] ^ _v[c], 7);
  }

  _incrementCounter(int n) {
    if (n == 0) return;
    _t[0] = _add32(_t[0], n);
    if (_t[0] == 0) _t[1]++;
  }

  _iterate() {
    var len = _pendingData.length;
    if (len > blockSize) {
      var index = 0;
      for (; (len - index) > blockSize; index += blockSize) {
        _bytesToWords(_pendingData, index, _currentBlockWords, _blockSizeInWords);
        _incrementCounter(blockSize);
        _compressBlock();
      }
      var remaining = len - index;
      _pendingData = _pendingData.getRange(index, remaining);
    }
  }

  _finalize() {
    _incrementCounter(_pendingData.length);
    // Pad with zeros.
    var numberOfZeros = blockSize - _pendingData.length;
    for (var i = 0; i < numberOfZeros; i++) {
      _pendingData.add(0);
    }
    // Set finalization flags.
    _f[0] = _MASK_32;
    if (_tree != null && _tree.isLastNode) _f[1] = _MASK_32;

    _bytesToWords(_pendingData, 0, _currentBlockWords, _blockSizeInWords);
    _compressBlock();
  }

  // Compute the final result as a list of bytes from the hash words.
  _resultAsBytes() {
    var result = [];
    for (var i = 0; i < _h.length; i++) {
      result.addAll(_wordToBytes(_h[i]));
    }
    return result.getRange(0, _digestLength);
  }

  // Finish the hash computation and return the digest string.
  List<int> close() {
    if (_digestCalled) {
      return _resultAsBytes();
    }
    _finalize();
    _digestCalled = true;
    return _resultAsBytes();
  }

  // Converts a list of bytes to a chunk of 32-bit words (little endian).
  _bytesToWords(List<int> data, int dataIndex, List<int> words, int numWords) {
    assert((data.length - dataIndex) >= (numWords * _BYTES_PER_WORD));

    for (var wordIndex = 0; wordIndex < numWords; wordIndex++) {
      words[wordIndex] =
          ((data[dataIndex] & _MASK_8)) |
          ((data[dataIndex + 1] & _MASK_8) << 8) |
          ((data[dataIndex + 2] & _MASK_8) << 16) |
          ((data[dataIndex + 3] & _MASK_8) << 24);
      dataIndex += 4;
    }
  }

  // Convert a 32-bit word to four bytes (little endian).
  _wordToBytes(int word) {
    List<int> bytes = new List(_BYTES_PER_WORD);
    bytes[0] = (word >> 0) & _MASK_8;
    bytes[1] = (word >> 8) & _MASK_8;
    bytes[2] = (word >> 16) & _MASK_8;
    bytes[3] = (word >> 24) & _MASK_8;
    return bytes;
  }
}
