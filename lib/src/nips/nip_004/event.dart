import 'package:bip340/bip340.dart' as bip340;

import '../../event.dart';
import '../../utils.dart';
import 'crypto.dart';


class EncryptedDirectMessage extends Event {

  static Map<String, List<List<int>>> gMapByteSecret = {};

  EncryptedDirectMessage(Event event)
      : super(
          event.id,
          event.pubkey,
          event.createdAt,
          4,
          event.tags,
          event.content,
          event.sig,
          subscriptionId: event.subscriptionId,
          verify: true,
        );

  factory EncryptedDirectMessage.quick(
    String senderPrivkey,
    String receiverPubkey,
    String message,
  ) {
    var event = Event.partial();
    event.pubkey = bip340.getPublicKey(senderPrivkey).toLowerCase();
    event.createdAt = currentUnixTimestampSeconds();
    event.kind = 4;
    event.tags = [
      ['p', receiverPubkey]
    ];
    event.content = Nip4.cipher(senderPrivkey, '02$receiverPubkey', message);
    event.id = event.getEventId();
    event.sig = event.getSignature(senderPrivkey);
    return EncryptedDirectMessage(event);
  }

  String? get receiverPubkey => findPubkey();

  String? findPubkey() {
    String prefix = "p";
    for (List<String> tag in tags) {
      if (tag.isNotEmpty && tag[0] == prefix && tag.length > 1) return tag[1];
    }
    return null;
  }

  String getCiphertext(String senderPrivkey, String receiverPubkey) {
    String ciphertext =
        Nip4.cipher(senderPrivkey, '02$receiverPubkey', content);
    return ciphertext;
  }

  String getPlaintext(String privkey, [String receiverPubkey=""]) {
    String plaintext = "FAILED TO DECRYPT";
    int ivIndex = content.indexOf("?iv=");
    if( ivIndex <= 0) {
      print("Invalid content for dm, could not get ivIndex: $content");
      return plaintext;
    }
    String iv = content.substring(ivIndex + "?iv=".length, content.length);
    String encString = content.substring(0, ivIndex);
    try {
      plaintext = Nip4.decrypt(privkey, "02" + pubkey, encString, iv);
    } catch(e) {
      print("Fail to decrypt: ${e}");
    }
    return plaintext;
  }
}
