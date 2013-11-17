/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.Interest;

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
    /* TODO
    // This will skip encoding if there is no publisherPublicKeyDigest.
    encodePublisherPublicKeyDigest(interest.getPublisherPublicKeyDigest(), encoder);
    // This will skip encoding if there is no exclude.
    encodeExclude(interest.getExclude(), encoder);
     */
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
    /* TODO
    decodeOptionalPublisherPublicKeyDigest(interest.publisherPublicKeyDigest, decoder);
    if (decoder.peekDTag(BinaryXml.DTag_Exclude))
      decodeExclude(interest.getExclude(), decoder);
    else
      interest.getExclude().clear();
     */
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
  
  // TODO: Make private after finished testing.
  public static void
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
}
