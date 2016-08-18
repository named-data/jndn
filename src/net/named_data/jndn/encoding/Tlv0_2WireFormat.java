/**
 * Copyright (C) 2016 Regents of the University of California.
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
import java.util.Random;

import net.named_data.jndn.ContentType;
import net.named_data.jndn.ControlParameters;
import net.named_data.jndn.ControlResponse;
import net.named_data.jndn.Data;
import net.named_data.jndn.DelegationSet;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.ForwardingFlags;
import net.named_data.jndn.GenericSignature;
import net.named_data.jndn.HmacWithSha256Signature;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.MetaInfo;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.lp.IncomingFaceId;
import net.named_data.jndn.lp.LpPacket;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.util.Blob;

/**
 * A Tlv0_2WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.2.
 */
public class Tlv0_2WireFormat extends WireFormat {
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
   * Decode input as a name in NDN-TLV and set the fields of the Name object.
   * @param name The Name object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeName(Name name, ByteBuffer input, boolean copy) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    decodeName(name, new int[1], new int[1], decoder, copy);
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
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.SelectedDelegation, interest.getSelectedDelegationIndex());
    try {
      Blob linkWireEncoding = interest.getLinkWireEncoding(this);
      if (!linkWireEncoding.isNull())
        // Encode the entire link as is.
        encoder.writeBuffer(linkWireEncoding.buf());
    } catch (EncodingException ex) {
      throw new Error(ex.getMessage());
    }

    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds());

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
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeInterest
    (Interest interest, ByteBuffer input, int[] signedPortionBeginOffset,
     int[] signedPortionEndOffset, boolean copy) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);

    int endOffset = decoder.readNestedTlvsStart(Tlv.Interest);
    decodeName
      (interest.getName(), signedPortionBeginOffset,signedPortionEndOffset,
       decoder, copy);
    if (decoder.peekType(Tlv.Selectors, endOffset))
      decodeSelectors(interest, decoder, copy);
    // Require a Nonce, but don't force it to be 4 bytes.
    ByteBuffer nonce = decoder.readBlobTlv(Tlv.Nonce);
    interest.setInterestLifetimeMilliseconds
      (decoder.readOptionalNonNegativeIntegerTlv(Tlv.InterestLifetime, endOffset));

    if (decoder.peekType(Tlv.Data, endOffset)) {
      // Get the bytes of the Link TLV.
      int linkBeginOffset = decoder.getOffset();
      int linkEndOffset = decoder.readNestedTlvsStart(Tlv.Data);
      decoder.seek(linkEndOffset);

      interest.setLinkWireEncoding
        (new Blob(decoder.getSlice(linkBeginOffset, linkEndOffset), copy), this);
    }
    else
      interest.unsetLink();
    interest.setSelectedDelegationIndex
      ((int)decoder.readOptionalNonNegativeIntegerTlv
       (Tlv.SelectedDelegation, endOffset));
    if (interest.getSelectedDelegationIndex() >= 0 && !interest.hasLink())
      throw new EncodingException
        ("Interest has a selected delegation, but no link object");

    // Set the nonce last because setting other interest fields clears it.
    interest.setNonce(new Blob(nonce, copy));

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
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeData
    (Data data, ByteBuffer input, int[] signedPortionBeginOffset,
     int[] signedPortionEndOffset, boolean copy) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);

    int endOffset = decoder.readNestedTlvsStart(Tlv.Data);
    signedPortionBeginOffset[0] = decoder.getOffset();

    decodeName(data.getName(), new int[1], new int[1], decoder, copy);
    decodeMetaInfo(data.getMetaInfo(), decoder, copy);
    data.setContent(new Blob(decoder.readBlobTlv(Tlv.Content), copy));
    decodeSignatureInfo(data, decoder, copy);

    signedPortionEndOffset[0] = decoder.getOffset();
    data.getSignature().setSignature
      (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy));

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
    encodeControlParameters(controlParameters, encoder);
    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a control parameters in NDN-TLV and set the fields of the
   * controlParameters object.
   * @param controlParameters The ControlParameters object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding
   */
  public void
  decodeControlParameters
    (ControlParameters controlParameters, ByteBuffer input, boolean copy)
    throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    decodeControlParameters(controlParameters, decoder, copy);
  }

  /**
   * Encode controlResponse in NDN-TLV and return the encoding.
   * @param controlResponse The ControlResponse object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeControlResponse(ControlResponse controlResponse)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.

    // Encode the body.
    if (controlResponse.getBodyAsControlParameters() != null)
      encodeControlParameters
        (controlResponse.getBodyAsControlParameters(), encoder);

    encoder.writeBlobTlv(Tlv.NfdCommand_StatusText,
      new Blob(controlResponse.getStatusText()).buf());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.NfdCommand_StatusCode, controlResponse.getStatusCode());

    encoder.writeTypeAndLength
      (Tlv.NfdCommand_ControlResponse, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a control parameters in NDN-TLV and set the fields of the
   * controlResponse object.
   * @param controlResponse The ControlResponse object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding
   */
  public void
  decodeControlResponse
    (ControlResponse controlResponse, ByteBuffer input, boolean copy)
    throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);

    controlResponse.setStatusCode
      ((int)decoder.readNonNegativeIntegerTlv(Tlv.NfdCommand_StatusCode));
    // Set copy false since we just immediately get a string.
    Blob statusText = new Blob
      (decoder.readBlobTlv(Tlv.NfdCommand_StatusText), false);
    controlResponse.setStatusText(statusText.toString());

    // Decode the body.
    if (decoder.peekType(Tlv.ControlParameters_ControlParameters, endOffset)) {
      controlResponse.setBodyAsControlParameters(new ControlParameters());
      // Decode into the existing ControlParameters to avoid copying.
      decodeControlParameters
        (controlResponse.getBodyAsControlParameters(), decoder, copy);
    }
    else
      controlResponse.setBodyAsControlParameters(null);

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
    public Data setSignature(Signature signature)
    {
      signature_ = signature;
      return null;
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
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @return A new object which is a subclass of Signature.
   * @throws EncodingException For invalid encoding.
   */
  public Signature
  decodeSignatureInfoAndValue
    (ByteBuffer signatureInfo, ByteBuffer signatureValue, boolean copy)
    throws EncodingException
  {
    // Use a SignatureHolder to imitate a Data object for _decodeSignatureInfo.
    SimpleSignatureHolder signatureHolder = new SimpleSignatureHolder();
    TlvDecoder decoder = new TlvDecoder(signatureInfo);
    decodeSignatureInfo(signatureHolder, decoder, copy);

    decoder = new TlvDecoder(signatureValue);
    signatureHolder.getSignature().setSignature
      (new Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy));

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
   * Decode input as an NDN-TLV LpPacket and set the fields of the lpPacket object.
   * @param lpPacket The LpPacket object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeLpPacket
    (LpPacket lpPacket, ByteBuffer input, boolean copy) throws EncodingException
  {
    lpPacket.clear();

    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.readNestedTlvsStart(Tlv.LpPacket_LpPacket);

    while (decoder.getOffset() < endOffset) {
      // Imitate TlvDecoder.readTypeAndLength.
      int fieldType = decoder.readVarNumber();
      int fieldLength = decoder.readVarNumber();
      int fieldEndOffset = decoder.getOffset() + fieldLength;
      if (fieldEndOffset > input.limit())
        throw new EncodingException("TLV length exceeds the buffer length");

      if (fieldType == Tlv.LpPacket_Fragment) {
        // Set the fragment to the bytes of the TLV value.
        lpPacket.setFragmentWireEncoding
          (new Blob(decoder.getSlice(decoder.getOffset(), fieldEndOffset), copy));
        decoder.seek(fieldEndOffset);

        // The fragment is supposed to be the last field.
        break;
      }
      else if (fieldType == Tlv.LpPacket_Nack) {
        NetworkNack networkNack = new NetworkNack();
        int code = (int)decoder.readOptionalNonNegativeIntegerTlv
          (Tlv.LpPacket_NackReason, fieldEndOffset);
        // The enum numeric values are the same as this wire format, so use as is.
        if (code < 0 || code == NetworkNack.Reason.NONE.getNumericType())
          // This includes an omitted NackReason.
          networkNack.setReason(NetworkNack.Reason.NONE);
        else if (code == NetworkNack.Reason.CONGESTION.getNumericType())
          networkNack.setReason(NetworkNack.Reason.CONGESTION);
        else if (code == NetworkNack.Reason.DUPLICATE.getNumericType())
          networkNack.setReason(NetworkNack.Reason.DUPLICATE);
        else if (code == NetworkNack.Reason.NO_ROUTE.getNumericType())
          networkNack.setReason(NetworkNack.Reason.NO_ROUTE);
        else {
          // Unrecognized reason.
          networkNack.setReason(NetworkNack.Reason.OTHER_CODE);
          networkNack.setOtherReasonCode(code);
        }

        lpPacket.addHeaderField(networkNack);
      }
      else if (fieldType == Tlv.LpPacket_IncomingFaceId) {
        IncomingFaceId incomingFaceId = new IncomingFaceId();
        incomingFaceId.setFaceId(decoder.readNonNegativeInteger(fieldLength));
        lpPacket.addHeaderField(incomingFaceId);
      }
      else {
        // Unrecognized field type. The conditions for ignoring are here:
        // http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
        boolean canIgnore =
          (fieldType >= Tlv.LpPacket_IGNORE_MIN &&
           fieldType <= Tlv.LpPacket_IGNORE_MAX &&
           (fieldType & 0x01) == 1);
        if (!canIgnore)
          throw new EncodingException("Did not get the expected TLV type");

        // Ignore.
        decoder.seek(fieldEndOffset);
      }

      decoder.finishNestedTlvs(fieldEndOffset);
    }

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Encode delegationSet as a sequence of NDN-TLV Delegation, and return the
   * encoding. Note that the sequence of Delegation does not have an outer TLV
   * type and length because it is intended to use the type and length of a Data
   * packet's Content.
   * @param delegationSet The DelegationSet object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeDelegationSet(DelegationSet delegationSet)
  {
    TlvEncoder encoder = new TlvEncoder(256);

    // Encode backwards.
    for (int i = delegationSet.size() - 1; i >= 0; --i) {
      int saveLength = encoder.getLength();

      encodeName(delegationSet.get(i).getName(), new int[1], new int[1], encoder);
      encoder.writeNonNegativeIntegerTlv
        (Tlv.Link_Preference, delegationSet.get(i).getPreference());

      encoder.writeTypeAndLength
        (Tlv.Link_Delegation, encoder.getLength() - saveLength);
    }

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a sequence of NDN-TLV Delegation and set the fields of the
   * delegationSet object. Note that the sequence of Delegation does not have an
   * outer TLV type and length because it is intended to use the type and length
   * of a Data packet's Content. This ignores any elements after the sequence
   * of Delegation and before input.limit().
   * @param delegationSet The DelegationSet object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeDelegationSet
    (DelegationSet delegationSet, ByteBuffer input, boolean copy)
    throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = input.limit();

    delegationSet.clear();
    while (decoder.getOffset() < endOffset) {
      decoder.readTypeAndLength(Tlv.Link_Delegation);
      int preference = (int)decoder.readNonNegativeIntegerTlv(Tlv.Link_Preference);
      Name name = new Name();
      decodeName(name, new int[1], new int[1], decoder, copy);

      // Add unsorted to preserve the order so that Interest selected delegation
      // index will work.
      delegationSet.addUnsorted(preference, name);
    }
  }

  /**
   * Encode the EncryptedContent in NDN-TLV and return the encoding.
   * @param encryptedContent The EncryptedContent object to encode.
   * @return A Blob containing the encoding.
   */
  public Blob
  encodeEncryptedContent(EncryptedContent encryptedContent)
  {
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    encoder.writeBlobTlv
      (Tlv.Encrypt_EncryptedPayload, encryptedContent.getPayload().buf());
    encoder.writeOptionalBlobTlv
      (Tlv.Encrypt_InitialVector, encryptedContent.getInitialVector().buf());
    // Assume the algorithmType value is the same as the TLV type.
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_EncryptionAlgorithm,
       encryptedContent.getAlgorithmType().getNumericType());
    Tlv0_2WireFormat.encodeKeyLocator
      (Tlv.KeyLocator, encryptedContent.getKeyLocator(), encoder);

    encoder.writeTypeAndLength
      (Tlv.Encrypt_EncryptedContent, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode input as a EncryptedContent in NDN-TLV and set the fields of the
   * encryptedContent object.
   * @param encryptedContent The EncryptedContent object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException For invalid encoding
   */
  public void
  decodeEncryptedContent
    (EncryptedContent encryptedContent, ByteBuffer input, boolean copy)
    throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.readNestedTlvsStart
      (Tlv.Encrypt_EncryptedContent);

    Tlv0_2WireFormat.decodeKeyLocator
      (Tlv.KeyLocator, encryptedContent.getKeyLocator(), decoder, copy);

    int algorithmType = (int)decoder.readNonNegativeIntegerTlv
       (Tlv.Encrypt_EncryptionAlgorithm);
    if (algorithmType == EncryptAlgorithmType.AesEcb.getNumericType())
      encryptedContent.setAlgorithmType(EncryptAlgorithmType.AesEcb);
    else if (algorithmType == EncryptAlgorithmType.AesCbc.getNumericType())
      encryptedContent.setAlgorithmType(EncryptAlgorithmType.AesCbc);
    else if (algorithmType == EncryptAlgorithmType.RsaPkcs.getNumericType())
      encryptedContent.setAlgorithmType(EncryptAlgorithmType.RsaPkcs);
    else if (algorithmType == EncryptAlgorithmType.RsaOaep.getNumericType())
      encryptedContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep);
    else
      throw new EncodingException
        ("Unrecognized EncryptionAlgorithm code " + algorithmType);

    encryptedContent.setInitialVector
      (new Blob(decoder.readOptionalBlobTlv
        (Tlv.Encrypt_InitialVector, endOffset), copy));
    encryptedContent.setPayload
      (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), copy));

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Get a singleton instance of a Tlv0_2WireFormat.  To always use the
   * preferred version NDN-TLV, you should use TlvWireFormat.get().
   * @return The singleton instance.
   */
  public static Tlv0_2WireFormat
  get()
  {
    return instance_;
  }

  /**
   * Encode the name component to the encoder as NDN-TLV. This handles different
   * component types such as ImplicitSha256DigestComponent.
   * @param component The name component to encode.
   * @param encoder The TlvEncoder to receive the encoding.
   */
  private static void
  encodeNameComponent(Name.Component component, TlvEncoder encoder)
  {
    int type = component.isImplicitSha256Digest() ?
      Tlv.ImplicitSha256DigestComponent : Tlv.NameComponent;
    encoder.writeBlobTlv(type, component.getValue().buf());
  }

  /**
   * Decode the name component as NDN-TLV and return the component. This handles
   * different component types such as ImplicitSha256DigestComponent.
   * @param decoder The decoder with the input to decode.
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @return A new Name.Component.
   * @throws EncodingException
   */
  private static Name.Component
  decodeNameComponent(TlvDecoder decoder, boolean copy) throws EncodingException
  {
    int savePosition = decoder.getOffset();
    int type = decoder.readVarNumber();
    // Restore the position.
    decoder.seek(savePosition);

    Blob value = new Blob(decoder.readBlobTlv(type), copy);
    if (type == Tlv.ImplicitSha256DigestComponent)
      return Name.Component.fromImplicitSha256Digest(value);
    else
      return new Name.Component(value);
  }

  /**
   * Encode the name as NDN-TLV to the encoder.
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
      encodeNameComponent(name.get(i), encoder);
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
   * @param copy If true, copy from the input when making new Blob values. If
   * false, then Blob values share memory with the input, which must remain
   * unchanged while the Blob values are used.
   * @throws EncodingException
   */
  private static void
  decodeName
    (Name name, int[] signedPortionBeginOffset, int[] signedPortionEndOffset,
     TlvDecoder decoder, boolean copy) throws EncodingException
  {
    name.clear();

    int endOffset = decoder.readNestedTlvsStart(Tlv.Name);

    signedPortionBeginOffset[0] = decoder.getOffset();
    // In case there are no components, set signedPortionEndOffset arbitrarily.
    signedPortionEndOffset[0] = signedPortionBeginOffset[0];

    while (decoder.getOffset() < endOffset) {
      signedPortionEndOffset[0] = decoder.getOffset();
      name.append(decodeNameComponent(decoder, copy));
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

    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents());
    encoder.writeOptionalNonNegativeIntegerTlv(
      Tlv.MinSuffixComponents, interest.getMinSuffixComponents());

    // Only output the type and length if values were written.
    if (encoder.getLength() != saveLength)
      encoder.writeTypeAndLength(Tlv.Selectors, encoder.getLength() - saveLength);
  }

  private static void
  decodeSelectors
    (Interest interest, TlvDecoder decoder, boolean copy) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.Selectors);

    interest.setMinSuffixComponents((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.MinSuffixComponents, endOffset));
    interest.setMaxSuffixComponents((int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.MaxSuffixComponents, endOffset));

    if (decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset))
      decodeKeyLocator
        (Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder, copy);
    else
      interest.getKeyLocator().clear();

    if (decoder.peekType(Tlv.Exclude, endOffset))
      decodeExclude(interest.getExclude(), decoder, copy);
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
        encodeNameComponent(entry.getComponent(), encoder);
    }

    encoder.writeTypeAndLength(Tlv.Exclude, encoder.getLength() - saveLength);
  }

  private static void
  decodeExclude
    (Exclude exclude, TlvDecoder decoder, boolean copy) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.Exclude);

    exclude.clear();
    while (decoder.getOffset() < endOffset) {
      if (decoder.peekType(Tlv.Any, endOffset)) {
        // Read past the Any TLV.
        decoder.readBooleanTlv(Tlv.Any, endOffset);
        exclude.appendAny();
      }
      else
        exclude.appendComponent(decodeNameComponent(decoder, copy));
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
    (int expectedType, KeyLocator keyLocator, TlvDecoder decoder, boolean copy)
    throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(expectedType);

    keyLocator.clear();

    if (decoder.getOffset() == endOffset)
      // The KeyLocator is omitted, so leave the fields as none.
      return;

    if (decoder.peekType(Tlv.Name, endOffset)) {
      // KeyLocator is a Name.
      keyLocator.setType(KeyLocatorType.KEYNAME);
      decodeName(keyLocator.getKeyName(), new int[1], new int[1], decoder, copy);
    }
    else if (decoder.peekType(Tlv.KeyLocatorDigest, endOffset)) {
      // KeyLocator is a KeyLocatorDigest.
      keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
      keyLocator.setKeyData
        (new Blob(decoder.readBlobTlv(Tlv.KeyLocatorDigest), copy));
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
    if (signature instanceof GenericSignature) {
      // Handle GenericSignature separately since it has the entire encoding.
      Blob encoding = ((GenericSignature)signature).getSignatureInfoEncoding();

      // Do a test decoding to sanity check that it is valid TLV.
      try {
        TlvDecoder decoder = new TlvDecoder(encoding.buf());
        int endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);
        decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
        decoder.finishNestedTlvs(endOffset);
      } catch (EncodingException ex) {
        throw new Error
          ("The GenericSignature encoding is not a valid NDN-TLV SignatureInfo: " +
           ex.getMessage());
      }

      encoder.writeBuffer(encoding.buf());
      return;
    }

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
    else if (signature instanceof HmacWithSha256Signature) {
      encodeKeyLocator
        (Tlv.KeyLocator, ((HmacWithSha256Signature)signature).getKeyLocator(),
         encoder);
      encoder.writeNonNegativeIntegerTlv
        (Tlv.SignatureType, Tlv.SignatureType_SignatureHmacWithSha256);
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
    (SignatureHolder signatureHolder, TlvDecoder decoder, boolean copy)
    throws EncodingException
  {
    int beginOffset = decoder.getOffset();
    int endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo);

    int signatureType = (int)decoder.readNonNegativeIntegerTlv(Tlv.SignatureType);
    if (signatureType == Tlv.SignatureType_SignatureSha256WithRsa) {
        signatureHolder.setSignature(new Sha256WithRsaSignature());
        // Modify the holder's signature object because if we create an object
        //   and set it, then the holder will have to copy all the fields.
        Sha256WithRsaSignature signatureInfo =
          (Sha256WithRsaSignature)signatureHolder.getSignature();
        decodeKeyLocator
          (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
    }
    else if (signatureType == Tlv.SignatureType_SignatureSha256WithEcdsa) {
        signatureHolder.setSignature(new Sha256WithEcdsaSignature());
        Sha256WithEcdsaSignature signatureInfo =
          (Sha256WithEcdsaSignature)signatureHolder.getSignature();
        decodeKeyLocator
          (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
    }
    else if (signatureType == Tlv.SignatureType_SignatureHmacWithSha256) {
        signatureHolder.setSignature(new HmacWithSha256Signature());
        HmacWithSha256Signature signatureInfo =
          (HmacWithSha256Signature)signatureHolder.getSignature();
        decodeKeyLocator
          (Tlv.KeyLocator, signatureInfo.getKeyLocator(), decoder, copy);
    }
    else if (signatureType == Tlv.SignatureType_DigestSha256)
        signatureHolder.setSignature(new DigestSha256Signature());
    else {
      signatureHolder.setSignature(new GenericSignature());
      GenericSignature signatureInfo =
        (GenericSignature)signatureHolder.getSignature();

      // Get the bytes of the SignatureInfo TLV.
      signatureInfo.setSignatureInfoEncoding
        (new Blob(decoder.getSlice(beginOffset, endOffset), copy), signatureType);
    }

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
      encodeNameComponent(metaInfo.getFinalBlockId(), encoder);
      encoder.writeTypeAndLength
        (Tlv.FinalBlockId, encoder.getLength() - finalBlockIdSaveLength);
    }

    encoder.writeOptionalNonNegativeIntegerTlvFromDouble
      (Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod());
    if (!(metaInfo.getType() == ContentType.BLOB)) {
      // Not the default, so we need to encode the type.
      if (metaInfo.getType() == ContentType.LINK ||
          metaInfo.getType() == ContentType.KEY ||
          metaInfo.getType() == ContentType.NACK)
        // The ContentType enum is set up with the correct integer for
        // each NDN-TLV ContentType.
        encoder.writeNonNegativeIntegerTlv
          (Tlv.ContentType, metaInfo.getType().getNumericType());
      else if (metaInfo.getType() == ContentType.OTHER_CODE)
        encoder.writeNonNegativeIntegerTlv
          (Tlv.ContentType, metaInfo.getOtherTypeCode());
      else
        // We don't expect this to happen.
        throw new Error("unrecognized TLV ContentType");
    }

    encoder.writeTypeAndLength(Tlv.MetaInfo, encoder.getLength() - saveLength);
  }

  private static void
  decodeMetaInfo
    (MetaInfo metaInfo, TlvDecoder decoder, boolean copy) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo);

    // The ContentType enum is set up with the correct integer for each
    // NDN-TLV ContentType.
    int type = (int)decoder.readOptionalNonNegativeIntegerTlv
      (Tlv.ContentType, endOffset);
    if (type < 0 || type == ContentType.BLOB.getNumericType())
      // Default to BLOB if the value is omitted.
      metaInfo.setType(ContentType.BLOB);
    else if (type == ContentType.LINK.getNumericType())
      metaInfo.setType(ContentType.LINK);
    else if (type == ContentType.KEY.getNumericType())
      metaInfo.setType(ContentType.KEY);
    else if (type == ContentType.NACK.getNumericType())
      metaInfo.setType(ContentType.NACK);
    else {
      // Unrecognized content type.
      metaInfo.setType(ContentType.OTHER_CODE);
      metaInfo.setOtherTypeCode(type);
    }

    metaInfo.setFreshnessPeriod
      (decoder.readOptionalNonNegativeIntegerTlv(Tlv.FreshnessPeriod, endOffset));
    if (decoder.peekType(Tlv.FinalBlockId, endOffset)) {
      int finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId);
      metaInfo.setFinalBlockId(decodeNameComponent(decoder, copy));
      decoder.finishNestedTlvs(finalBlockIdEndOffset);
    }
    else
      metaInfo.setFinalBlockId(null);

    decoder.finishNestedTlvs(endOffset);
  }

  private static void
  encodeControlParameters(ControlParameters controlParameters, TlvEncoder encoder)
  {
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
    if(controlParameters.getUri().length() != 0){
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
  }

  private static void
  decodeControlParameters
    (ControlParameters controlParameters, TlvDecoder decoder, boolean copy)
    throws EncodingException
  {
    controlParameters.clear();

    int endOffset = decoder.readNestedTlvsStart
      (Tlv.ControlParameters_ControlParameters);

    // decode name
    if (decoder.peekType(Tlv.Name, endOffset)) {
      Name name = new Name();
      decodeName(name, new int[1], new int[1], decoder, copy);
      controlParameters.setName(name);
    }

    // decode face ID
    controlParameters.setFaceId
      ((int)decoder.readOptionalNonNegativeIntegerTlv
       (Tlv.ControlParameters_FaceId, endOffset));

    // decode URI
    if (decoder.peekType(Tlv.ControlParameters_Uri, endOffset)) {
      // Set copy false since we just immediately get the string.
      Blob uri = new Blob
        (decoder.readOptionalBlobTlv(Tlv.ControlParameters_Uri, endOffset), false);
      controlParameters.setUri("" + uri);
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
      int strategyEndOffset = decoder.readNestedTlvsStart
        (Tlv.ControlParameters_Strategy);
      decodeName
        (controlParameters.getStrategy(), new int[1], new int[1], decoder, copy);
      decoder.finishNestedTlvs(strategyEndOffset);
    }

    // decode expiration period
    controlParameters.setExpirationPeriod
      (decoder.readOptionalNonNegativeIntegerTlv
       (Tlv.ControlParameters_ExpirationPeriod, endOffset));

    decoder.finishNestedTlvs(endOffset);
  }

  private static final Random random_ = new Random();
  private static Tlv0_2WireFormat instance_ = new Tlv0_2WireFormat();
}
