/**
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.ControlParameters;
import net.named_data.jndn.Data;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.ForwardingFlags;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.LocalControlHeader;
import net.named_data.jndn.MetaInfo;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.SignatureHolder;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

/**
 * A Tlv0_1_1WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.1.1.
 */
public class Tlv0_1_1WireFormat extends WireFormat {
  /**
   * Encode name in NDN-TLV and return the encoding.
   * @param name The Name object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeName(Name name)
  {
    TlvEncoder encoder = new TlvEncoder();
    encodeName(name, new int[1], new int[1], encoder);
    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a name in NDN-TLV and set the fields of the interest object.
   * @param name The Name object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeName(Name name, ByteBuffer input) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    decodeName(name, new int[1], new int[1], decoder);
  }

  /**
   * Encode interest using NDN-TLV and return the encoding.
   * @param interest The Interest object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeInterest
    (Interest interest, int[] signedPortionBeginOffset, int[] signedPortionEndOffset)
  {
    TlvEncoder encoder = new TlvEncoder();
    int saveLength = encoder.getLength();

    // Encode backwards.
    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());
    // Access scope_ directly to avoid throwing a deprecated exception.
    encoder.writeOptionalNonNegativeIntegerTlv(Tlv.Scope, interest.scope_);

    // Encode the Nonce as 4 bytes.
    if (interest.getNonce().size() == 0)
    {
      // This is the most common case. Generate a nonce.
      ByteBuffer nonce = ByteBuffer.allocate(4);
      random_.nextBytes(nonce.array());
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
    int[] tempSignedPortionBeginOffset = new int[1];
    int[] tempSignedPortionEndOffset = new int[1];
    encodeName
      (interest.getName(), tempSignedPortionBeginOffset,
       tempSignedPortionEndOffset, encoder);
    int signedPortionBeginOffsetFromBack =
      encoder.getLength() - tempSignedPortionBeginOffset[0];
    int signedPortionEndOffsetFromBack =
      encoder.getLength() - tempSignedPortionEndOffset[0];

    encoder.writeTypeAndLength(Tlv.Interest, encoder.getLength() - saveLength);
    signedPortionBeginOffset[0] =
      encoder.getLength() - signedPortionBeginOffsetFromBack;
    signedPortionEndOffset[0] =
      encoder.getLength() - signedPortionEndOffsetFromBack;

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as an interest in  NDN-TLV and set the fields of the interest
   * object.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeInterest
    (Interest interest, ByteBuffer input, int[] signedPortionBeginOffset,
     int[] signedPortionEndOffset) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);

    int endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
    decodeName
      (interest.getName(), signedPortionBeginOffset,signedPortionEndOffset,
       decoder);
    if (decoder.peekType(Tlv.Selectors, endOffset))
      decodeSelectors(interest, decoder);
    // Require a Nonce, but don't force it to be 4 bytes.
    ByteBuffer nonce = decoder.readBlobTlv(Tlv.Nonce);
    // Access scope_ directly to avoid throwing a deprecated exception.
    interest.scope_ = (int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.Scope, endOffset);
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
    encoder.writeBlobTlv
      (Tlv.SignatureValue, (data.getSignature()).getSignature().buf());
    int signedPortionEndOffsetFromBack = encoder.getLength();

    encodeSignatureInfo(data.getSignature(), encoder);
    encoder.writeBlobTlv(Tlv.Content, data.getContent().buf());
    encodeMetaInfo(data.getMetaInfo(), encoder);
    encodeName(data.getName(), new int[1], new int[1], encoder);
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

    decodeName(data.getName(), new int[1], new int[1], decoder);
    decodeMetaInfo(data.getMetaInfo(), decoder);
    data.setContent(new Blob(decoder.readBlobTlv(Tlv.Content), true));
    decodeSignatureInfo(data, decoder);

    signedPortionEndOffset[0] = decoder.getOffset();
    data.getSignature().setSignature
      (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Encode controlParameters in NDN-TLV and return the encoding.
   * @param controlParameters The ControlParameters object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeControlParameters(ControlParameters controlParameters)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.ControlParameters_ExpirationPeriod,
       controlParameters.getExpirationPeriod());

    // Encode strategy
    if(controlParameters.getStrategy().size() != 0){
      int strategySaveLength = encoder.getLength();
      encodeName(controlParameters.getStrategy(), new int[1], new int[1],
        encoder);
      encoder.writeTypeAndLength(Tlv.ControlParameters_Strategy,
        encoder.getLength() - strategySaveLength);
    }

    // Encode ForwardingFlags
    int flags = controlParameters.getForwardingFlags().getNfdForwardingFlags();
    if (flags != new ForwardingFlags().getNfdForwardingFlags())
        // The flags are not the default value.
        encoder.writeNonNegativeIntegerTlv(Tlv.ControlParameters_Flags, flags);

    encoder.writeOptionalNonNegativeIntegerTlv
      (Tlv.ControlParameters_Cost, controlParameters.getCost());
    encoder.writeOptionalNonNegativeIntegerTlv
      (Tlv.ControlParameters_Origin, controlParameters.getOrigin());
    encoder.writeOptionalNonNegativeIntegerTlv
      (Tlv.ControlParameters_LocalControlFeature,
       controlParameters.getLocalControlFeature());

    // Encode URI
    if(!controlParameters.getUri().isEmpty()){
      encoder.writeBlobTlv(Tlv.ControlParameters_Uri,
        new Blob(controlParameters.getUri()).buf());
    }

    encoder.writeOptionalNonNegativeIntegerTlv
      (Tlv.ControlParameters_FaceId, controlParameters.getFaceId());

    // Encode name
    if (controlParameters.getName() != null) {
      encodeName(controlParameters.getName(), new int[1], new int[1], encoder);
    }

    encoder.writeTypeAndLength
      (Tlv.ControlParameters_ControlParameters, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a control parameters in NDN-TLV and set the fields of the
   * controlParameters object.
   * @param controlParameters The ControlParameters object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding
   */
  public void
  decodeControlParameters
    (ControlParameters controlParameters, ByteBuffer input)
    throws EncodingException
  {
    controlParameters.clear();

    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.
      readNestedTlvsStart(Tlv.ControlParameters_ControlParameters);

    // decode name
    if (decoder.peekType(Tlv.Name, endOffset)) {
      Name name = new Name();
      decodeName(name, new int[1], new int[1], decoder);
      controlParameters.setName(name);
    }

    // decode face ID
    controlParameters.setFaceId((int) decoder.readOptionalNonNegativeIntegerTlv(Tlv.ControlParameters_FaceId, endOffset));

    // decode URI
    if (decoder.peekType(Tlv.ControlParameters_Uri, endOffset)) {
      Blob uri = new Blob(decoder.readOptionalBlobTlv(Tlv.ControlParameters_Uri, endOffset), true);
      controlParameters.setUri(uri.toString());
    }

    // decode integers
    controlParameters.setLocalControlFeature((int) decoder.
      readOptionalNonNegativeIntegerTlv(
        Tlv.ControlParameters_LocalControlFeature, endOffset));
    controlParameters.setOrigin((int) decoder.
      readOptionalNonNegativeIntegerTlv(Tlv.ControlParameters_Origin,
        endOffset));
    controlParameters.setCost((int) decoder.readOptionalNonNegativeIntegerTlv(
      Tlv.ControlParameters_Cost, endOffset));

    // set forwarding flags
    if (decoder.peekType(Tlv.ControlParameters_Flags, endOffset)) {
      ForwardingFlags flags = new ForwardingFlags();
      flags.setNfdForwardingFlags((int) decoder.
        readNonNegativeIntegerTlv(Tlv.ControlParameters_Flags));
      controlParameters.setForwardingFlags(flags);
    }

    // decode strategy
    if (decoder.peekType(Tlv.ControlParameters_Strategy, endOffset)) {
      int strategyEndOffset = decoder.readNestedTlvsStart(Tlv.ControlParameters_Strategy);
      decodeName(controlParameters.getStrategy(), new int[1], new int[1], decoder);
      decoder.finishNestedTlvs(strategyEndOffset);
    }

    // decode expiration period
    controlParameters.setExpirationPeriod(decoder.readOptionalNonNegativeIntegerTlv(Tlv.ControlParameters_ExpirationPeriod, endOffset));

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Encode signature as a SignatureInfo in NDN-TLV and return the encoding.
   * @param signature An object of a subclass of Signature to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeSignatureInfo(Signature signature)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    encodeSignatureInfo(signature, encoder);

    return new Blob(encoder.getOutput(), false);
  }

  private static class SimpleSignatureHolder implements SignatureHolder {
    public SignatureHolder setSignature(Signature signature)
    {
      signature_ = signature;
      return this;
    }

    public Signature getSignature()
    {
      return signature_;
    }

    private Signature signature_;
  }

  /**
   * Decode signatureInfo as an NDN-TLV signature info and signatureValue as the
   * related NDN-TLV SignatureValue, and return a new object which is a subclass
   * of Signature.
   * @param signatureInfo The signature info input buffer to decode. This reads
   * from position() to limit(), but does not change the position.
   * @param signatureValue The signature value input buffer to decode. This reads
   * from position() to limit(), but does not change the position.
   * @return A new object which is a subclass of Signature.
   * @throws EncodingException For invalid encoding.
   */
  public Signature
  decodeSignatureInfoAndValue
    (ByteBuffer signatureInfo, ByteBuffer signatureValue) throws EncodingException
  {
    // Use a SignatureHolder to imitate a Data object for _decodeSignatureInfo.
    SimpleSignatureHolder signatureHolder = new SimpleSignatureHolder();
    TlvDecoder decoder = new TlvDecoder(signatureInfo);
    decodeSignatureInfo(signatureHolder, decoder);

    decoder = new TlvDecoder(signatureValue);
    signatureHolder.getSignature().setSignature
      (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), true));

    return signatureHolder.getSignature();
  }

  /**
   * Encode the signatureValue in the Signature object as a SignatureValue (the
   * signature bits) in NDN-TLV and return the encoding.
   * @param signature An object of a subclass of Signature with the signature
   * value to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeSignatureValue(Signature signature)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf());

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Encode the LocalControlHeader in NDN-TLV and return the encoding.
   * @param localControlHeader The LocalControlHeader object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeLocalControlHeader(LocalControlHeader localControlHeader)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    // Encode the entire payload as is.
    encoder.writeBuffer(localControlHeader.getPayloadWireEncoding().buf());

    // TODO: Encode CachingPolicy when we want to include it for an outgoing Data.
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.LocalControlHeader_NextHopFaceId, localControlHeader.getNextHopFaceId());
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.LocalControlHeader_IncomingFaceId, localControlHeader.getIncomingFaceId());

    encoder.writeTypeAndLength
      (Tlv.LocalControlHeader_LocalControlHeader, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a LocalControlHeader in NDN-TLV and set the fields of the
   * localControlHeader object.
   * @param localControlHeader The LocalControlHeader object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding
   */
  public void
  decodeLocalControlHeader
    (LocalControlHeader localControlHeader, ByteBuffer input)
    throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.
      readNestedTlvsStart(Tlv.LocalControlHeader_LocalControlHeader);

    localControlHeader.setIncomingFaceId(decoder.readOptionalNonNegativeIntegerTlv(
      Tlv.LocalControlHeader_IncomingFaceId, endOffset));
    localControlHeader.setNextHopFaceId(decoder.readOptionalNonNegativeIntegerTlv(
      Tlv.LocalControlHeader_NextHopFaceId, endOffset));

    // Ignore CachingPolicy. // TODO: Process CachingPolicy when we want the
    // client library to receive it for an incoming Data.
    if (decoder.peekType(Tlv.LocalControlHeader_CachingPolicy, endOffset)) {
      int cachingPolicyEndOffset = decoder.readNestedTlvsStart
        (Tlv.LocalControlHeader_CachingPolicy);
      decoder.finishNestedTlvs(cachingPolicyEndOffset);
    }

    // Set the payload to a slice of the remaining input.
    ByteBuffer payload = input.duplicate();
    payload.limit(endOffset);
    payload.position(decoder.getOffset());
    localControlHeader.setPayloadWireEncoding(new Blob(payload, false));

    // Don't call finishNestedTlvs since we got the payload and don't want to
    // decode any of it now.
  }

  /**
   * Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the
   * preferred version NDN-TLV, you should use TlvWireFormat.get().
   * @return The singleton instance.
   */
  public static Tlv0_1_1WireFormat
  get()
  {
    return instance_;
  }

  /**
   * Encode the name to the encoder.
   * @param name The name to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param encoder The TlvEncoder to receive the encoding.
   */
  private static void
  encodeName
    (Name name, int[] signedPortionBeginOffset, int[] signedPortionEndOffset,
     TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode the components backwards.
    int signedPortionEndOffsetFromBack = 0;
    for (int i = name.size() - 1; i >= 0; --i) {
      encoder.writeBlobTlv(Tlv.NameComponent, name.get(i).getValue().buf());
      if (i == name.size() - 1)
          signedPortionEndOffsetFromBack = encoder.getLength();
    }

    int signedPortionBeginOffsetFromBack = encoder.getLength();
    encoder.writeTypeAndLength(Tlv.Name, encoder.getLength() - saveLength);

    signedPortionBeginOffset[0] =
      encoder.getLength() - signedPortionBeginOffsetFromBack;
    if (name.size() == 0)
        // There is no "final component", so set signedPortionEndOffset
        //   arbitrarily.
        signedPortionEndOffset[0] = signedPortionBeginOffset[0];
    else
        signedPortionEndOffset[0] =
          encoder.getLength() - signedPortionEndOffsetFromBack;
  }

  /**
   * Decode the name as NDN-TLV and set the fields in name.
   * @param name The name object whose fields are set.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can ignore this returned value.
   * @param decoder The decoder with the input to decode.
   * @throws EncodingException
   */
  private static void
  decodeName
    (Name name, int[] signedPortionBeginOffset, int[] signedPortionEndOffset,
     TlvDecoder decoder) throws EncodingException
  {
    name.clear();

    int endOffset = decoder.readNestedTlvsStart(Tlv.Name);

    signedPortionBeginOffset[0] = decoder.getOffset();
    // In case there are no components, set signedPortionEndOffset arbitrarily.
    signedPortionEndOffset[0] = signedPortionBeginOffset[0];

    while (decoder.getOffset() < endOffset) {
      signedPortionEndOffset[0] = decoder.getOffset();
      name.append(new Blob(decoder.readBlobTlv(Tlv.NameComponent), true));
    }

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

    if (interest.getKeyLocator().getType() != KeyLocatorType.NONE)
      encodeKeyLocator
        (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder);
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
    if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset)) {
      decodeKeyLocator
        (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder);
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
  encodeKeyLocator(int type, KeyLocator keyLocator, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    if (keyLocator.getType() != KeyLocatorType.NONE) {
      if (keyLocator.getType() == KeyLocatorType.KEYNAME)
        encodeName(keyLocator.getKeyName(), new int[1], new int[1], encoder);
      else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
               keyLocator.getKeyData().size() > 0)
        encoder.writeBlobTlv(Tlv.KeyLocatorDigest, keyLocator.getKeyData().buf());
      else
        throw new Error("Unrecognized KeyLocatorType " + keyLocator.getType());
    }

    encoder.writeTypeAndLength(type, encoder.getLength() - saveLength);
  }

  private static void
  decodeKeyLocator
    (int expectedType, KeyLocator keyLocator, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(expectedType);

    keyLocator.clear();

    if (decoder.getOffset() == endOffset)
      // The KeyLocator is omitted, so leave the fields as none.
      return;

    if (decoder.peekType(Tlv.Name, endOffset)) {
      // KeyLocator is a Name.
      keyLocator.setType(KeyLocatorType.KEYNAME);
      decodeName(keyLocator.getKeyName(), new int[1], new int[1], decoder);
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

  /**
   * An internal method to encode signature as the appropriate form of
   * SignatureInfo in NDN-TLV.
   * @param signature An object of a subclass of Signature to encode.
   * @param encoder The TlvEncoder to receive the encoding.
   */
  private void
  encodeSignatureInfo(Signature signature, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    if (signature instanceof Sha256WithRsaSignature) {
      encodeKeyLocator
        (Tlv.KeyLocator, ((Sha256WithRsaSignature)signature).getKeyLocator(),
         encoder);
      encoder.writeNonNegativeIntegerTlv
        (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa);
    }
    else if (signature instanceof Sha256WithEcdsaSignature) {
      encodeKeyLocator
        (Tlv.KeyLocator, ((Sha256WithEcdsaSignature)signature).getKeyLocator(),
         encoder);
      encoder.writeNonNegativeIntegerTlv
        (Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithEcdsa);
    }
    else if (signature instanceof DigestSha256Signature)
      encoder.writeNonNegativeIntegerTlv
        (Tlv.SignatureType, Tlv.SignatureType_DigestSha256);
    else
      throw new Error("encodeSignatureInfo: Unrecognized Signature object type");

    encoder.writeTypeAndLength
      (Tlv.SignatureInfo, encoder.getLength() - saveLength);
  }

  private static void
  decodeSignatureInfo
    (SignatureHolder signatureHolder, TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

    int signatureType = (int)decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
    if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
        signatureHolder.setSignature(new Sha256WithRsaSignature());
        // Modify data's signature object because if we create an object
        //   and set it, then data will have to copy all the fields.
        Sha256WithRsaSignature signatureInfo =
          (Sha256WithRsaSignature)signatureHolder.getSignature();
        decodeKeyLocator(Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
    }
    else if (signatureType == Tlv.SignatureType_SignatureSha256WithEcdsa) {
        signatureHolder.setSignature(new Sha256WithEcdsaSignature());
        Sha256WithEcdsaSignature signatureInfo =
          (Sha256WithEcdsaSignature)signatureHolder.getSignature();
        decodeKeyLocator(Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder);
    }
    else if (signatureType == Tlv.SignatureType_DigestSha256)
        signatureHolder.setSignature(new DigestSha256Signature());
    else
        throw new EncodingException
         ("decodeSignatureInfo: unrecognized SignatureInfo type" + signatureType);

    decoder.finishNestedTlvs(endOffset);
  }

  private static void
  encodeMetaInfo(MetaInfo metaInfo, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    ByteBuffer finalBlockIdBuf = metaInfo.getFinalBlockId().getValue().buf();
    if (finalBlockIdBuf != null && finalBlockIdBuf.remaining() > 0) {
      // FinalBlockId has an inner NameComponent.
      int finalBlockIdSaveLength = encoder.getLength();
      encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf);
      encoder.writeTypeAndLength
        (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
    }

    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
    if (!(metaInfo.getType() == ContentType.BLOB ||
          metaInfo.getType() == ContentType.DATA)) {
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
  }

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
      metaInfo.setFinalBlockId
        (new Name.Component
         (new Blob(decoder.readBlobTlv(Tlv.NameComponent), true)));
      decoder.finishNestedTlvs(finalBlockIdEndOffset);
    }
    else
      metaInfo.setFinalBlockId(null);

    decoder.finishNestedTlvs(endOffset);
  }

  private static final SecureRandom random_ = new SecureRandom();
  private static Tlv0_1_1WireFormat instance_ = new Tlv0_1_1WireFormat();
}
