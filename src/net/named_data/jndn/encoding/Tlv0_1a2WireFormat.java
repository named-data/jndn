/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.security.SecureRandom;
import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Interest;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.encoding.tlv.TlvDecoder;

/**
 * A Tlv0_1a2WireFormat implements the WireFormat interface for encoding and 
 * decoding with the NDN-TLV wire format, version 0.1a2.
 */
public class Tlv0_1a2WireFormat extends WireFormat {
  /**
   * Encode interest using NDN-TLV and return the encoding.
   * @param interest The Interest object to encode.
   * @return A Blob containing the encoding.
   */  
  public Blob 
  encodeInterest(Interest interest)
  {
    TlvEncoder encoder = new TlvEncoder();
    int saveLength = encoder.getLength();

    // Encode backwards.
    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
    encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.getScope());

    // Encode the Nonce as 4 bytes.
    if (interest.getNonce().size() == 0)
    {
      ByteBuffer nonce = ByteBuffer.allocate(4);
      random_.nextBytes(nonce.array());
      // This is the most common case. Generate a nonce.
      encoder.writeBlobTlv(Tlv.Nonce, nonce);
    }
    else if (interest.getNonce().size() < 4) {
      ByteBuffer nonce = ByteBuffer.allocate(4);
      // Copy existing nonce bytes.
      nonce.put(interest.getNonce().buf());
 
      // Generate random bytes for remaining bytes in the nonce.
      for (int i = 0; i < 4 - interest.getNonce().size(); ++i)
        nonce.put((byte)random_.nextInt());

      nonce.flip();
      encoder.writeBlobTlv(Tlv.Nonce, nonce);
    }
    else if (interest.getNonce().size() == 4)
      // Use the nonce as-is.
      encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf());
    else
    {
      // Truncate.
      ByteBuffer nonce = interest.getNonce().buf();
      // buf() returns a new ByteBuffer, so we can change its limit.
      nonce.limit(nonce.position() + 4);
      encoder.writeBlobTlv(Tlv.Nonce, nonce);
    }

    encodeSelectors(interest, encoder);
    encodeName(interest.getName(), encoder);

    encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }
  
  /**
   * Decode input as an interest in  NDN-TLV and set the fields of the interest 
   * object.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to 
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeInterest(Interest interest, ByteBuffer input) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);

    int endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
    decodeName(interest.getName(), decoder);
    if (decoder.peekType(Tlv.Selectors, endOffset))
      decodeSelectors(interest, decoder);
    // Require a Nonce, but don't force it to be 4 bytes.
    ByteBuffer nonce = decoder.readBlobTlv(Tlv.Nonce);
    interest.setScope((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.Scope, endOffset));
    interest.setInterestLifetimeMilliseconds
      (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

    // Set the nonce last because setting other interest fields clears it.
    interest.setNonce(new Blob(nonce, true));

    decoder.finishNestedTlvs(endOffset);
  }
  
  /**
   * Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the 
   * preferred version NDN-TLV, you should use TlvWireFormat.get().
   * @return The singleton instance.
   */
  public static Tlv0_1a2WireFormat
  get()
  {
    return instance_;
  }
  
  private static void
  encodeName(Name name, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode the components backwards.
    for (int i = name.size() - 1; i >= 0; --i)
      encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue().buf());

    encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);
  }

  private static void
  decodeName(Name name, TlvDecoder decoder) throws EncodingException
  {
    name.clear();

    int endOffset = decoder.readNestedTlvsStart(Tlv.Name);      
    while (decoder.getOffset() < endOffset)
        name.append(new Blob(decoder.readBlobTlv(Tlv.NameComponent), true));

    decoder.finishNestedTlvs(endOffset);
  }
  
  /**
   * Encode the interest selectors.  If no selectors are written, do not output 
   * a  Selectors TLV.
   */
  private static void
  encodeSelectors(Interest interest, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    if (interest.getMustBeFresh())
      encoder.writeTypeAndLength(Tlv.MustBeFresh, 0);
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.ChildSelector, interest.getChildSelector());
    if (interest.getExclude().size() > 0)
      encodeExclude(interest.getExclude(), encoder);

    if (interest.getKeyLocator().getType() != null)
      encodeKeyLocator(interest.getKeyLocator(), encoder);
    else {
      // There is no keyLocator. If there is a publisherPublicKeyDigest, then 
      //   encode as KEY_LOCATOR_DIGEST. (When we remove the deprecated 
      //   publisherPublicKeyDigest, we don't need this.)
      if (interest.getPublisherPublicKeyDigest().getPublisherPublicKeyDigest().size() > 0) {
        int savePublisherPublicKeyDigestLength = encoder.getLength();
        encoder.writeBlobTlv
          (Tlv.KeyLocatorDigest, 
           interest.getPublisherPublicKeyDigest().getPublisherPublicKeyDigest().buf());
        encoder.writeTypeAndLength
          (Tlv.KeyLocator, encoder.getLength() - savePublisherPublicKeyDigestLength);
      }
    }

    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

    // Only output the type and length if values were written.
    if (encoder.getLength() != saveLength)
      encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
  }

  private static void
  decodeSelectors(Interest interest, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

    interest.setMinSuffixComponents((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.MinSuffixComponents, endOffset));
    interest.setMaxSuffixComponents((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.MaxSuffixComponents, endOffset));

    // Initially set publisherPublicKeyDigest to none.
    interest.getPublisherPublicKeyDigest().clear();
    if (decoder.peekType(Tlv.KeyLocator, endOffset)) {
      decodeKeyLocator(interest.getKeyLocator(), decoder);
      if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST) {
        // For backwards compatibility, also set the publisherPublicKeyDigest.
        interest.getPublisherPublicKeyDigest().setPublisherPublicKeyDigest
          (interest.getKeyLocator().getKeyData());
      }
    }
    else
      interest.getKeyLocator().clear();

    if (decoder.peekType(Tlv.Exclude, endOffset))
      decodeExclude(interest.getExclude(), decoder);
    else
      interest.getExclude().clear();

    interest.setChildSelector((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.ChildSelector, endOffset));
    interest.setMustBeFresh(decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset));

    decoder.finishNestedTlvs(endOffset);
  }
  
  private static void
  encodeExclude(Exclude exclude, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // TODO: Do we want to order the components (except for ANY)?
    // Encode the entries backwards.
    for (int i = exclude.size() - 1; i >= 0; --i) {
      Exclude.Entry entry = exclude.get(i);

      if (entry.getType() == Exclude.Type.ANY)
        encoder.writeTypeAndLength(Tlv.Any, 0);
      else
        encoder.writeBlobTlv
          (Tlv.NameComponent, entry.getComponent().getValue().buf());
    }

    encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
  }

  private static void
  decodeExclude(Exclude exclude, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

    exclude.clear();
    while (true) {
      if (decoder.peekType(Tlv.NameComponent, endOffset))
        exclude.appendComponent(new Name.Component
          (new Blob(decoder.readBlobTlv(Tlv.NameComponent), true)));
      else if (decoder.readBooleanTlv(Tlv.Any, endOffset))
        exclude.appendAny();
      else
        // Else no more entries.
        break;
    }

    decoder.finishNestedTlvs(endOffset);
  }

  private static void
  encodeKeyLocator(KeyLocator keyLocator, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    if (keyLocator.getType() != null) {
      if (keyLocator.getType() == KeyLocatorType.KEYNAME)
        encodeName(keyLocator.getKeyName(), encoder);
      else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
               keyLocator.getKeyData().size() > 0)
        encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
      else
        throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
    }

    encoder.writeTypeAndLength(Tlv.KeyLocator, encoder.getLength() - saveLength);
  }
  
  private static void
  decodeKeyLocator
    (KeyLocator keyLocator, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.KeyLocator);

    keyLocator.clear();

    if (decoder.getOffset() == endOffset)
      // The KeyLocator is omitted, so leave the fields as none.
      return;

    if (decoder.peekType(Tlv.Name, endOffset)) {
      // KeyLocator is a Name.
      keyLocator.setType(KeyLocatorType.KEYNAME);
      decodeName(keyLocator.getKeyName(), decoder);
    }
    else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
      // KeyLocator is a KeyLocatorDigest.
      keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
      keyLocator.setKeyData
        (new Blob(decoder.readBlobTlv(Tlv.KeyLocatorDigest), true));
    }
    else
      throw new EncodingException
        ("decodeKeyLocator: Unrecognized key locator type");

    decoder.finishNestedTlvs(endOffset);
  }
  
  private static final SecureRandom random_ = new SecureRandom();
  private static Tlv0_1a2WireFormat instance_ = new Tlv0_1a2WireFormat();
}
