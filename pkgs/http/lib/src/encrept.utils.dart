import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:tuple/tuple.dart';

class GenerateStamp {
  late int _timestamp;

  GenerateStamp() {
    _timestamp = DateTime.now().millisecondsSinceEpoch;
  }

  int getStamp() => _timestamp;

  String getXApiKey() {
    var apiKey = 'qwertyuiop12345zxcvbnmkjh';
    var data = IAuthApiRequestHashedData(
      key: apiKey,
      timestamp: _timestamp,
      hash: 'e11a023bc0ccf713cb50de9baa5140e59d3d4c52ec8952d9ca60326e040eda54',
    );
    var apiEncryption = AuthorizationRequest().createXApiKey(
      data: data,
      key: 'opbUwdiS1FBsrDUoPgZdx',
    );
    var xApiKey = '$apiKey:$apiEncryption';
    return xApiKey;
  }
}

class AuthorizationRequest {
  Uint8List _genRandomWithNonZero(int seedLength) {
    final random = Random.secure();
    const randomMax = 245;
    final uint8list = Uint8List(seedLength);
    for (var i = 0; i < seedLength; i++) {
      uint8list[i] = random.nextInt(randomMax) + 1;
    }
    return uint8list;
  }

  String createXApiKey({
    required IAuthApiRequestHashedData data,
    required String key,
  }) {
    try {
      final salt = _genRandomWithNonZero(8);
      var keyndIV = _deriveKeyAndIV(key, salt);
      final key2 = Key(keyndIV.item1);
      final iv = IV(keyndIV.item2);

      final encrypter = Encrypter(AES(key2, mode: AESMode.cbc, padding: 'PKCS7'));
      final encrypted = encrypter.encrypt(data.toString(), iv: iv);
      var encryptedBytesWithSalt =
          Uint8List.fromList(_createUint8ListFromString('Salted__') + salt + encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (e) {
      rethrow;
    }
  }

  Tuple2<Uint8List, Uint8List> _deriveKeyAndIV(String passphrase, Uint8List salt) {
    var password = _createUint8ListFromString(passphrase);
    var concatenatedHashes = Uint8List(0);
    List<int> currentHash = Uint8List(0);
    var enoughBytesForKey = false;
    var preHash = Uint8List(0);

    while (!enoughBytesForKey) {
      var preHashLength = currentHash.length + password.length + salt.length;
      if (currentHash.isNotEmpty) {
        preHash = Uint8List.fromList(currentHash + password + salt);
      } else {
        preHash = Uint8List.fromList(password + salt);
      }

      currentHash = md5.convert(preHash).bytes;
      concatenatedHashes = Uint8List.fromList(concatenatedHashes + currentHash);
      if (concatenatedHashes.length >= 48) enoughBytesForKey = true;
    }

    var keyBtyes = concatenatedHashes.sublist(0, 32);
    var ivBtyes = concatenatedHashes.sublist(32, 48);
    return Tuple2(keyBtyes, ivBtyes);
  }

  Uint8List _createUint8ListFromString(String s) {
    var ret = Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  String decryptAESCryptoJS({
    required String encrypted,
    required String key,
    required String iv,
  }) {
    try {
      var encryptedBytesWithSalt = base64.decode(encrypted);
      var encryptedBytes = encryptedBytesWithSalt.sublist(16, encryptedBytesWithSalt.length);
      final salt = encryptedBytesWithSalt.sublist(8, 16);
      var keyndIV = _deriveKeyAndIV(key, salt);
      final key2 = Key(keyndIV.item1);
      final iv = IV(keyndIV.item2);

      final encrypter = Encrypter(AES(key2, mode: AESMode.cbc, padding: 'Pkcs7'.toUpperCase()));
      final decrypted = encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}

class IAuthApiRequestHashedData {
  String key;
  int timestamp;
  String hash;

  IAuthApiRequestHashedData({required this.key, required this.timestamp, required this.hash});

  Map<String, dynamic> toJson() => {'key': key, 'timestamp': timestamp, 'hash': hash};

  @override
  String toString() => const JsonEncoder().convert(toJson());
}
