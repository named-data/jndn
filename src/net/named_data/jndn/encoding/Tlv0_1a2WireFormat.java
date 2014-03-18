/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.MetaInfo;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

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
   * Encode data in NDN-TLV and return the encoding.
   * @param data The Data object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the 
   * beginning of the signed portion by setting signedPortionBeginOffset[0].
   * If you are not encoding in order to sign, you can call encodeData(data) to 
   * ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end 
   * of the signed portion by setting signedPortionEndOffset[0].
   * If you are not encoding in order to sign, you can call encodeData(data) to 
   * ignore this returned value.
   * @return A Blob containing the encoding.
   */
  public Blob 
  encodeData
    (Data data, int[] signedPortionBeginOffset, int[] signedPortionEndOffset)
  {
    TlvEncoder encoder = new TlvEncoder(1500);
    int saveLength = encoder.getLength();

    // Encode backwards.
    // TODO: The library needs to handle other signature types than 
    //   SignatureSha256WithRsa.
    encoder.writeBlobTlv
      (Tlv.SignatureValue, 
       ((Sha256WithRsaSignature)data.getSignature()).getSignature().buf());
    int signedPortionEndOffsetFromBack = encoder.getLength();

    // Use getSignatureOrMetaInfoKeyLocator for the transition of moving
    //   the key locator from the MetaInfo to the Signauture object.
    Tlv0_1a2WireFormat.encodeSignatureSha256WithRsaValue
      ((Sha256WithRsaSignature)data.getSignature(), encoder);
    encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
    Tlv0_1a2WireFormat.encodeMetaInfo(data.getMetaInfo(), encoder);
    Tlv0_1a2WireFormat.encodeName(data.getName(), encoder);
    int signedPortionBeginOffsetFromBack = encoder.getLength();

    encoder.writeTypeAndLength(Tlv.Data, encoder.getLength() - saveLength);
    
    signedPortionBeginOffset[0] = 
      encoder.getLength() - signedPortionBeginOffsetFromBack;
    signedPortionEndOffset[0] = 
      encoder.getLength() - signedPortionEndOffsetFromBack;
    return new Blob(encoder.getOutput(), false);  
  }

  /**
   * Decode input as a data packet in NDN-TLV and set the fields in the data 
   * object.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to 
   * limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the input buffer of 
   * the beginning of the signed portion by setting signedPortionBeginOffset[0].  
   * If you are not decoding in order to verify, you can call 
   * decodeData(data, input) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the 
   * end of the signed portion by setting signedPortionEndOffset[0]. If you are 
   * not decoding in order to verify, you can call decodeData(data, input) to 
   * ignore this returned value.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeData
    (Data data, ByteBuffer input, int[] signedPortionBeginOffset, 
     int[] signedPortionEndOffset) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);  

    int endOffset = decoder.readNestedTlvsStart(Tlv.Data);
    signedPortionBeginOffset[0] = decoder.getOffset();

    decodeName(data.getName(), decoder);
    decodeMetaInfo(data.getMetaInfo(), decoder);
    data.setContent(new Blob(decoder.readBlobTlv(Tlv.Content), true));
    decodeSignatureInfo(data, decoder);

    signedPortionEndOffset[0] = decoder.getOffset();
    // TODO: The library needs to handle other signature types than 
    //   SignatureSha256WithRsa.
    ((Sha256WithRsaSignature)data.getSignature()).setSignature
      (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

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
    if (keyLocator.getType() != KeyLocatorType.NONE) {
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
  
  private static void
  encodeSignatureSha256WithRsaValue
    (Sha256WithRsaSignature signature, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    encodeKeyLocator(signature.getKeyLocator(), encoder);
    encoder.writeNonNegativeIntegerTlv
      (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);

    encoder.writeTypeAndLength
      (Tlv.SignatureInfo, encoder.getLength() - saveLength);
  };

  private static void
  decodeSignatureInfo(Data data, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

    int signatureType = (int)decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
    // TODO: The library needs to handle other signature types than 
    //     SignatureSha256WithRsa.
    if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
        data.setSignature(new Sha256WithRsaSignature());
        // Modify data's signature object because if we create an object
        //   and set it, then data will have to copy all the fields.
        Sha256WithRsaSignature signatureInfo = 
          (Sha256WithRsaSignature)data.getSignature();
        decodeKeyLocator(signatureInfo.getKeyLocator(), decoder);
    }
    else
        throw new EncodingException
         ("decodeSignatureInfo: unrecognized SignatureInfo type" + signatureType);

    decoder.finishNestedTlvs(endOffset);
  };

  private static void
  encodeMetaInfo(MetaInfo metaInfo, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    ByteBuffer finalBlockIdBuf = metaInfo.getFinalBlockID().getValue().buf();
    if (finalBlockIdBuf != null && finalBlockIdBuf.remaining() > 0) {
      // FinalBlockId has an inner NameComponent.
      int finalBlockIdSaveLength = encoder.getLength();
      encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf);
      encoder.writeTypeAndLength
        (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
    }

    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
    if (metaInfo.getType() != ContentType.BLOB) {
      // Not the default, so we need to encode the type.
      if (metaInfo.getType() == ContentType.LINK ||
          metaInfo.getType() == ContentType.KEY)
        // The ContentType enum is set up with the correct integer for 
        // each NDN-TLV ContentType.
        encoder.writeNonNegativeIntegerTlv
          (Tlv.ContentType, metaInfo.getType().getNumericType());
      else
        throw new Error("unrecognized TLV ContentType");
    }

    encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
  };

  private static void
  decodeMetaInfo(MetaInfo metaInfo, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);  

    // The ContentType enum is set up with the correct integer for each 
    // NDN-TLV ContentType.  If readOptionalNonNegativeIntegerTlv returns
    // None, then setType will convert it to BLOB.
    int type = (int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.ContentType, endOffset);
    if (type == ContentType.LINK.getNumericType())
      metaInfo.setType(ContentType.LINK);
    if (type == ContentType.KEY.getNumericType())
      metaInfo.setType(ContentType.KEY);
    else
      // Default to BLOB.
      metaInfo.setType(ContentType.BLOB);
    
    metaInfo.setFreshnessPeriod
      (decoder.readOptionalNonNegativeIntegerTlv(Tlv.FreshnessPeriod, endOffset));
    if (decoder.peekType(Tlv.FinalBlockId, endOffset)) {
      int finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId);
      metaInfo.setFinalBlockID
        (new Name.Component
         (new Blob(decoder.readBlobTlv(Tlv.NameComponent), true)));
      decoder.finishNestedTlvs(finalBlockIdEndOffset);
    }
    else
      metaInfo.setFinalBlockID(null);

    decoder.finishNestedTlvs(endOffset);
  };

  private static final SecureRandom random_ = new SecureRandom();
  private static Tlv0_1a2WireFormat instance_ = new Tlv0_1a2WireFormat();
}
