/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocator.KeyLocatorType;
import net.named_data.jndn.MetaInfo;
import net.named_data.jndn.MetaInfo.ContentType;
import net.named_data.jndn.Name;
import net.named_data.jndn.PublisherPublicKeyDigest;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.util.Blob;

public class BinaryXmlWireFormat extends WireFormat {
  /**
   * Encode interest in binary XML and return the encoding.
   * @param interest The Interest object to encode.
   * @return A Blob containing the encoding.
   */  
  @Override
  public Blob 
  encodeInterest(Interest interest)
  {
    BinaryXmlEncoder encoder = new BinaryXmlEncoder();
    encodeInterest(interest, encoder);
    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as an interest in binary XML and set the fields of the interest object.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  @Override
  public void 
  decodeInterest(Interest interest, ByteBuffer input) throws EncodingException
  {
    BinaryXmlDecoder decoder = new BinaryXmlDecoder(input);  
    decodeInterest(interest, decoder);
  }

  private static void
  encodeInterest(Interest interest, BinaryXmlEncoder encoder)
  {
    encoder.writeElementStartDTag(BinaryXml.DTag_Interest);

    encodeName(interest.getName(), encoder);
    encoder.writeOptionalUnsignedDecimalIntDTagElement(BinaryXml.DTag_MinSuffixComponents, interest.getMinSuffixComponents());
    encoder.writeOptionalUnsignedDecimalIntDTagElement(BinaryXml.DTag_MaxSuffixComponents, interest.getMaxSuffixComponents());
    // This will skip encoding if there is no publisherPublicKeyDigest.
    encodePublisherPublicKeyDigest(interest.getPublisherPublicKeyDigest(), encoder);
    // This will skip encoding if there is no exclude.
    encodeExclude(interest.getExclude(), encoder);
    encoder.writeOptionalUnsignedDecimalIntDTagElement(BinaryXml.DTag_ChildSelector, interest.getChildSelector());
    if (interest.getAnswerOriginKind() >= 0 && interest.getAnswerOriginKind() != Interest.DEFAULT_ANSWER_ORIGIN_KIND)
      encoder.writeUnsignedDecimalIntDTagElement(BinaryXml.DTag_AnswerOriginKind, interest.getAnswerOriginKind());
    encoder.writeOptionalUnsignedDecimalIntDTagElement(BinaryXml.DTag_Scope, interest.getScope());
    encoder.writeOptionalTimeMillisecondsDTagElement(BinaryXml.DTag_InterestLifetime, interest.getInterestLifetimeMilliseconds());
    encoder.writeOptionalBlobDTagElement(BinaryXml.DTag_Nonce, interest.getNonce());

    encoder.writeElementClose();
  }

  private static void
  decodeInterest(Interest interest, BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_Interest);

    decodeName(interest.getName(), decoder);
    interest.setMinSuffixComponents(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_MinSuffixComponents));
    interest.setMaxSuffixComponents(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_MaxSuffixComponents));
    decodeOptionalPublisherPublicKeyDigest(interest.getPublisherPublicKeyDigest(), decoder);

    if (decoder.peekDTag(BinaryXml.DTag_Exclude))
      decodeExclude(interest.getExclude(), decoder);
    else
      interest.getExclude().clear();
    
    interest.setChildSelector(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_ChildSelector));
    interest.setAnswerOriginKind(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_AnswerOriginKind));
    interest.setScope(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_Scope));
    interest.setInterestLifetimeMilliseconds(decoder.readOptionalTimeMillisecondsDTagElement(BinaryXml.DTag_InterestLifetime));
    interest.setNonce(new Blob(decoder.readOptionalBinaryDTagElement(BinaryXml.DTag_Nonce, false), true));

    decoder.readElementClose();
  }
    
  private static void
  encodeName(Name name, BinaryXmlEncoder encoder)
  {
    encoder.writeElementStartDTag(BinaryXml.DTag_Name);

    for (int i = 0; i < name.size(); ++i)
      encoder.writeBlobDTagElement(BinaryXml.DTag_Component, name.get(i).getValue());

    encoder.writeElementClose();
  }
  
  private static void
  decodeName(Name name, BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_Name);
    name.clear();
    while (true) {
      if (!decoder.peekDTag(BinaryXml.DTag_Component))
        // No more components.
        break;

      name.append
        (new Blob(decoder.readBinaryDTagElement(BinaryXml.DTag_Component, false), true));
    }

    decoder.readElementClose();
  }
  
  /**
   * Decode input as a data packet in binary XML and set the fields in the data object.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the input buffer of the beginning of the signed portion by
   * setting signedPortionBeginOffset[0].  If you are not decoding in order to verify, you can call 
   * decodeData(data, input) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the end of the signed portion by
   * setting signedPortionEndOffset[0]. If you are not decoding in order to verify, you can call 
   * decodeData(data, input) to ignore this returned value.
   * @throws UnsupportedOperationException for unimplemented if the derived class does not override.
   * @throws EncodingException For invalid encoding.
   */
  @Override
  public void 
  decodeData(Data data, ByteBuffer input, int[] signedPortionBeginOffset, int[] signedPortionEndOffset) throws EncodingException
  {
    BinaryXmlDecoder decoder = new BinaryXmlDecoder(input);  
    decodeData(data, input, signedPortionBeginOffset, signedPortionEndOffset, decoder);
  }
  
  private static void
  decodeData(Data data, ByteBuffer input, int[] signedPortionBeginOffset, int[] signedPortionEndOffset, 
              BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_ContentObject);

    data.setSignature(new Sha256WithRsaSignature());
    if (decoder.peekDTag(BinaryXml.DTag_Signature))
      decodeSignature((Sha256WithRsaSignature)data.getSignature(), decoder);

    signedPortionBeginOffset[0] = decoder.getOffset();

    decodeName(data.getName(), decoder);
    data.setMetaInfo(new MetaInfo());
    if (decoder.peekDTag(BinaryXml.DTag_SignedInfo))
      decodeSignedInfo((Sha256WithRsaSignature)data.getSignature(), data.getMetaInfo(), decoder);
    // Require a Content element, but set allowNull to allow a missing BLOB.
    data.setContent(new Blob(decoder.readBinaryDTagElement(BinaryXml.DTag_Content, true), true));

    signedPortionEndOffset[0] = decoder.getOffset();

    decoder.readElementClose();
  }
  
  /**
   * Encode the PublisherPublicKeyDigest using Binary XML.  If publisherPublicKeyDigest.getPublisherPublicKeyDigest().size()
   * is 0, then do nothing. 
   * @param publisherPublicKeyDigest The PublisherPublicKeyDigest to encode.
   * @param encoder The BinaryXmlEncoder used to encode.
   */
  private static void
  encodePublisherPublicKeyDigest(PublisherPublicKeyDigest publisherPublicKeyDigest, BinaryXmlEncoder encoder)
  {  
    if (publisherPublicKeyDigest.getPublisherPublicKeyDigest().size() <= 0)
      return;

    encoder.writeBlobDTagElement(BinaryXml.DTag_PublisherPublicKeyDigest, publisherPublicKeyDigest.getPublisherPublicKeyDigest());
  }

  /**
   * Expect the next element to be a Binary XML PublisherPublicKeyDigest and decode into publisherPublicKeyDigest.
   * @param publisherPublicKeyDigest The PublisherPublicKeyDigest to update.
   * @param decoder The BinaryXmlDecoder used to decode.
   * @throws EncodingException For invalid encoding.
   */
  private static void
  decodePublisherPublicKeyDigest
    (PublisherPublicKeyDigest publisherPublicKeyDigest, BinaryXmlDecoder decoder) throws EncodingException
  {
    publisherPublicKeyDigest.setPublisherPublicKeyDigest
      (new Blob(decoder.readBinaryDTagElement(BinaryXml.DTag_PublisherPublicKeyDigest, false), true));
  }

  /**
   * Peek the next element and if it is a Binary XML PublisherPublicKeyDigest decode into publisherPublicKeyDigest.
   * Otherwise, set publisherPublicKeyDigest to none.
   * @param publisherPublicKeyDigest The PublisherPublicKeyDigest to update.
   * @param decoder The BinaryXmlDecoder used to decode.
   * @throws EncodingException For invalid encoding.
   */
  private static void
  decodeOptionalPublisherPublicKeyDigest
    (PublisherPublicKeyDigest publisherPublicKeyDigest, BinaryXmlDecoder decoder) throws EncodingException
  {
    if (decoder.peekDTag(BinaryXml.DTag_PublisherPublicKeyDigest))
      decodePublisherPublicKeyDigest(publisherPublicKeyDigest, decoder);
    else
      publisherPublicKeyDigest.clear();
  }
  
  private static void 
  encodeExclude(Exclude exclude, BinaryXmlEncoder encoder)
  {
    if (exclude.size() <= 0)
      // Omit.
      return;

    encoder.writeElementStartDTag(BinaryXml.DTag_Exclude);

    // TODO: Do we want to order the components (except for ANY)?
    for (int i = 0; i < exclude.size(); ++i) {
      Exclude.Entry entry = exclude.get(i);

      if (entry.getType() == Exclude.Type.COMPONENT)
        encoder.writeBlobDTagElement(BinaryXml.DTag_Component, entry.getComponent().getValue());
      else {
        // Type is ANY.
        encoder.writeElementStartDTag(BinaryXml.DTag_Any);
        encoder.writeElementClose();
      }
    }

    encoder.writeElementClose();
  }

  private static void
  decodeExclude(Exclude exclude, BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_Exclude);

    exclude.clear();
    while (true) {
      if (decoder.peekDTag(BinaryXml.DTag_Component))
        exclude.appendComponent(new Name.Component(new Blob(decoder.readBinaryDTagElement(BinaryXml.DTag_Component, false), true)));
      else if (decoder.peekDTag(BinaryXml.DTag_Any)) {
        // Read the Any element.
        decoder.readElementStartDTag(BinaryXml.DTag_Any);
        decoder.readElementClose();
        
        exclude.appendAny();
      }
      else if (decoder.peekDTag(BinaryXml.DTag_Bloom)) {
        // Skip the Bloom and treat it as Any.
        decoder.readBinaryDTagElement(BinaryXml.DTag_Bloom, false);
        exclude.appendAny();
      }
      else
        // No more entries.
        break;
    }

    decoder.readElementClose();
  }
  
  private static void
  encodeSignature(Sha256WithRsaSignature signature, BinaryXmlEncoder encoder)
  {
    encoder.writeElementStartDTag(BinaryXml.DTag_Signature);
    
    // TODO: Check if digestAlgorithm is the same as the default, and skip it, otherwise encode it as UDATA.
    encoder.writeOptionalBlobDTagElement(BinaryXml.DTag_Witness, signature.getWitness());
    // Require a signature.
    encoder.writeBlobDTagElement(BinaryXml.DTag_SignatureBits, signature.getSignature());
    encoder.writeElementClose();
  }  
  
  private static void
  decodeSignature(Sha256WithRsaSignature signature, BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_Signature);
    /* TODO: digestAlgorithm as UDATA */ signature.setDigestAlgorithm(new Blob());
    signature.setWitness(new Blob(decoder.readOptionalBinaryDTagElement(BinaryXml.DTag_Witness, false), true));
    // Require a signature.
    signature.setSignature(new Blob(decoder.readBinaryDTagElement(BinaryXml.DTag_SignatureBits, false), true));
    decoder.readElementClose();
  }

  /**
   * Encode the ndn_KeyLocator struct using Binary XML.  If keyLocator.getType() == KeyLocatorType.NONE, then do nothing. 
   * @param keyLocator The KeyLocator to encode.
   * @param encoder The BinaryXmlEncoder used to encode.
   */
  private static void
  encodeKeyLocator(KeyLocator keyLocator, BinaryXmlEncoder encoder)
  {
    if (keyLocator.getType() == KeyLocatorType.NONE)
      return;

    // TODO: Implement.
  }
  
  /**
   *  Expect the next element to be a Binary XML KeyLocator and decode into keyLocator.
   * @param keyLocator The KeyLocator to update.
   * @param decoder The BinaryXmlDecoder used to decode.
   * @throws EncodingException For invalid encoding.
   */
  private static void
  decodeKeyLocator(KeyLocator keyLocator, BinaryXmlDecoder decoder) throws EncodingException
  {  
    // TODO: Implement. For now, skip.
    BinaryXmlStructureDecoder structureDecoder = new BinaryXmlStructureDecoder();
    structureDecoder.seek(decoder.getOffset());
    structureDecoder.findElementEnd(decoder.input_);
    decoder.seek(structureDecoder.getOffset());
  }
  
  /**
   * Peek the next element and if it is a Binary XML KeyLocator then decode into the keyLocator.
   * Otherwise, call keyLocator.clear().
   * @param keyLocator The KeyLocator to update.
   * @param decoder The BinaryXmlDecoder used to decode.
   * @throws EncodingException For invalid encoding.
   */
  private static void
  decodeOptionalKeyLocator(KeyLocator keyLocator, BinaryXmlDecoder decoder) throws EncodingException
  {
    if (decoder.peekDTag(BinaryXml.DTag_KeyLocator))
      decodeKeyLocator(keyLocator, decoder);
    else
      keyLocator.clear();
  }
  
  // Put these in a Blob so we can use ByteBuffer equals.
  private static final Blob DATA_BYTES = new Blob(ByteBuffer.wrap(new byte[] { (byte)0x0C, (byte)0x04, (byte)0xC0 }), false);
  private static final Blob ENCR_BYTES = new Blob(ByteBuffer.wrap(new byte[] { (byte)0x10, (byte)0xD0, (byte)0x91 }), false);
  private static final Blob GONE_BYTES = new Blob(ByteBuffer.wrap(new byte[] { (byte)0x18, (byte)0xE3, (byte)0x44 }), false);
  private static final Blob KEY_BYTES =  new Blob(ByteBuffer.wrap(new byte[] { (byte)0x28, (byte)0x46, (byte)0x3F }), false);
  private static final Blob LINK_BYTES = new Blob(ByteBuffer.wrap(new byte[] { (byte)0x2C, (byte)0x83, (byte)0x4A }), false);
  private static final Blob NACK_BYTES = new Blob(ByteBuffer.wrap(new byte[] { (byte)0x34, (byte)0x00, (byte)0x8A }), false);
  
  private static void
  encodeSignedInfo(Sha256WithRsaSignature signature, MetaInfo metaInfo, BinaryXmlEncoder encoder)
  {
    encoder.writeElementStartDTag(BinaryXml.DTag_SignedInfo);
    // This will skip encoding if there is no publisherPublicKeyDigest.
    encodePublisherPublicKeyDigest(signature.getPublisherPublicKeyDigest(), encoder);
    encoder.writeOptionalTimeMillisecondsDTagElement(BinaryXml.DTag_Timestamp, metaInfo.getTimestampMilliseconds());
    if (metaInfo.getType() != ContentType.DATA) {
      // Not the default of DATA, so we need to encode the type.
      Blob typeBytes = null;;
      if (metaInfo.getType() == ContentType.ENCR)
        typeBytes = ENCR_BYTES;
      else if (metaInfo.getType() == ContentType.GONE)
        typeBytes = GONE_BYTES;
      else if (metaInfo.getType() == ContentType.KEY)
        typeBytes = KEY_BYTES;
      else if (metaInfo.getType() == ContentType.LINK)
        typeBytes = LINK_BYTES;
      else if (metaInfo.getType() == ContentType.NACK)
        typeBytes = NACK_BYTES;

      encoder.writeBlobDTagElement(BinaryXml.DTag_Type, typeBytes);
    }

    encoder.writeOptionalUnsignedDecimalIntDTagElement(BinaryXml.DTag_FreshnessSeconds, metaInfo.getFreshnessSeconds());
    encoder.writeOptionalBlobDTagElement(BinaryXml.DTag_FinalBlockID, metaInfo.getFinalBlockID().getValue());
    // This will skip encoding if there is no key locator.
    encodeKeyLocator(signature.getKeyLocator(), encoder);
    encoder.writeElementClose();
  }

  private static void
  decodeSignedInfo(Sha256WithRsaSignature signature, MetaInfo metaInfo, BinaryXmlDecoder decoder) throws EncodingException
  {
    decoder.readElementStartDTag(BinaryXml.DTag_SignedInfo);
    decodeOptionalPublisherPublicKeyDigest(signature.getPublisherPublicKeyDigest(), decoder);
    metaInfo.setTimestampMilliseconds(decoder.readOptionalTimeMillisecondsDTagElement(BinaryXml.DTag_Timestamp));
    ByteBuffer typeBytes = decoder.readOptionalBinaryDTagElement(BinaryXml.DTag_Type, false);
    if (typeBytes == null)
      // The default Type is DATA.
      metaInfo.setType(ContentType.DATA);
    else {
      if (typeBytes.equals(DATA_BYTES.buf()))
        metaInfo.setType(ContentType.DATA);
      else if (typeBytes.equals(ENCR_BYTES.buf()))
        metaInfo.setType(ContentType.ENCR);
      else if (typeBytes.equals(GONE_BYTES.buf()))
        metaInfo.setType(ContentType.GONE);
      else if (typeBytes.equals(KEY_BYTES.buf()))
        metaInfo.setType(ContentType.KEY);
      else if (typeBytes.equals(LINK_BYTES.buf()))
        metaInfo.setType(ContentType.LINK);
      else if (typeBytes.equals(NACK_BYTES.buf()))
        metaInfo.setType(ContentType.NACK);
      else
        throw new EncodingException("Unrecognized MetaInfo.ContentType");
    }

    metaInfo.setFreshnessSeconds(decoder.readOptionalUnsignedIntegerDTagElement(BinaryXml.DTag_FreshnessSeconds));
    metaInfo.setFinalBlockID(new Name.Component(new Blob(decoder.readOptionalBinaryDTagElement(BinaryXml.DTag_FinalBlockID, false), true)));
    decodeOptionalKeyLocator(signature.getKeyLocator(), decoder);
    decoder.readElementClose();
  }  
}
