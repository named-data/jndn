/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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
import net.named_data.jndn.ControlParameters;
import net.named_data.jndn.Data;
import net.named_data.jndn.DelegationSet;
import net.named_data.jndn.Interest;
import net.named_data.jndn.LocalControlHeader;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.util.Blob;

public class WireFormat {
  /**
   * Encode name and return the encoding.  Your derived class should
   * override.
   * @param name The Name object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeName(Name name)
  {
    throw new UnsupportedOperationException("encodeName is not implemented");
  }

  /**
   * Decode input as a name and set the fields of the Name object.
   * Your derived class should override.
   * @param name The Name object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeName(Name name, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException("decodeName is not implemented");
  }

  /**
   * Encode interest and return the encoding.  Your derived class should
   * override.
   * @param interest The Interest object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not encoding in order to sign, you can call
   * encodeInterest(const Interest& interest) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not encoding in order to sign, you can call
   * encodeInterest(const Interest& interest) to ignore this returned value.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeInterest(Interest interest, int[] signedPortionBeginOffset, int[] signedPortionEndOffset)
  {
    throw new UnsupportedOperationException
      ("encodeInterest is not implemented");
  }

  /**
   * Encode interest and return the encoding.  Your derived class should
   * override.
   * @param interest The Interest object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public final Blob
  encodeInterest(Interest interest)
  {
    return encodeInterest(interest, new int[1], new int[1]);
  }

  /**
   * Decode input as an interest and set the fields of the interest object.
   * Your derived class should override.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can call
   * decodeInterest(Interest interest, ByteBuffer input)
   * to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can call
   * decodeInterest(Interest interest, ByteBuffer input)
   * to ignore this returned value.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeInterest
    (Interest interest, ByteBuffer input, int[] signedPortionBeginOffset,
     int[] signedPortionEndOffset) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeInterest is not implemented");
  }

  /**
   * Decode input as an interest and set the fields of the interest object.
   * Your derived class should override.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  decodeInterest(Interest interest, ByteBuffer input) throws EncodingException
  {
    decodeInterest(interest, input, new int[1], new int[1]);
  }

  /**
   * Encode data and return the encoding.  Your derived class should override.
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
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeData
    (Data data, int[] signedPortionBeginOffset, int[] signedPortionEndOffset)
  {
    throw new UnsupportedOperationException("encodeData is not implemented");
  }

  /**
   * Encode data and return the encoding.
   * @param data The Data object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public final Blob
  encodeData(Data data)
  {
    return encodeData(data, new int[1], new int[1]);
  }

  /**
   * Decode input as a data packet and set the fields in the data object.  Your
   * derived class should override.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the input buffer of
   * the beginning of the signed portion by setting signedPortionBeginOffset[0].
   * If you are not decoding in order to verify, you can call
   * decodeData(data, input) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the
   * end of the signed portion by
   * setting signedPortionEndOffset[0]. If you are not decoding in order to
   * verify, you can call decodeData(data, input) to ignore this returned value.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeData
    (Data data, ByteBuffer input, int[] signedPortionBeginOffset,
     int[] signedPortionEndOffset) throws EncodingException
  {
    throw new UnsupportedOperationException("decodeData is not implemented");
  }

  /**
   * Decode input as a data packet and set the fields in the data object.  Your
   * derived class should override.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  decodeData(Data data, ByteBuffer input) throws EncodingException
  {
    decodeData(data, input, new int[1], new int[1]);
  }

  /**
   * Encode controlParameters and return the encoding.
   * Your derived class should override.
   * @param controlParameters The ControlParameters object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeControlParameters(ControlParameters controlParameters)
  {
    throw new UnsupportedOperationException
      ("encodeControlParameters is not implemented");
  }

  /**
   * Decode input as a control parameters and set the fields of the
   * controlParameters object.  Your derived class should override.
   * @param controlParameters The ControlParameters object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeControlParameters
    (ControlParameters controlParameters, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeControlParameters is not implemented");
  }

  /**
   * Encode signature as a SignatureInfo and return the encoding.
   * Your derived class should override.
   * @param signature An object of a subclass of Signature to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeSignatureInfo(Signature signature)
  {
    throw new UnsupportedOperationException
      ("encodeSignatureInfo is not implemented");
  }

  /**
   * Decode signatureInfo as a signature info and signatureValue as the related
   * SignatureValue, and return a new object which is a subclass of Signature.
   * Your derived class should override.
   * @param signatureInfo The signature info input buffer to decode. This reads
   * from position() to limit(), but does not change the position.
   * @param signatureValue The signature value input buffer to decode. This reads
   * from position() to limit(), but does not change the position.
   * @return A new object which is a subclass of Signature.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public Signature
  decodeSignatureInfoAndValue
    (ByteBuffer signatureInfo, ByteBuffer signatureValue) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeSignatureInfoAndValue is not implemented");
  }

  /**
   * Encode the signatureValue in the Signature object as a SignatureValue (the
   * signature bits) and return the encoding.
   * Your derived class should override.
   * @param signature An object of a subclass of Signature with the signature
   * value to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeSignatureValue(Signature signature)
  {
    throw new UnsupportedOperationException
      ("encodeSignatureValue is not implemented");
  }

  /**
   * Encode the LocalControlHeader and return the encoding. Your
   * derived class should override.
   * @param localControlHeader The LocalControlHeader object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeLocalControlHeader(LocalControlHeader localControlHeader)
  {
    throw new UnsupportedOperationException
      ("encodeLocalControlHeader is not implemented");
  }

  /**
   * Decode input as a LocalControlHeader and set the fields of the
   * localControlHeader object. Your derived class should override.
   * @param localControlHeader The LocalControlHeader object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public void
  decodeLocalControlHeader
    (LocalControlHeader localControlHeader, ByteBuffer input)
    throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeLocalControlHeader is not implemented");
  }

  /**
   * Encode delegationSet and return the encoding.
   * Your derived class should override.
   * @param delegationSet The DelegationSet object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeDelegationSet(DelegationSet delegationSet)
  {
    throw new UnsupportedOperationException
      ("encodeDelegationSet is not implemented");
  }

  /**
   * Decode input as a delegation set and set the fields of the
   * delegationSet object.  Your derived class should override.
   * @param delegationSet The DelegationSet object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void
  decodeDelegationSet
    (DelegationSet delegationSet, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeDelegationSet is not implemented");
  }
  /**
   * Encode the EncryptedContent and return the encoding. Your derived class
   * should override.
   * @param encryptedContent The EncryptedContent object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public Blob
  encodeEncryptedContent(EncryptedContent encryptedContent)
  {
    throw new UnsupportedOperationException
      ("encodeEncryptedContent is not implemented");
  }

  /**
   * Decode input as an EncryptedContent and set the fields of the
   * encryptedContent object. Your derived class should override.
   * @param encryptedContent The EncryptedContent object whose fields are
   * updated.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived
   * class does not override.
   */
  public void
  decodeEncryptedContent
    (EncryptedContent encryptedContent, ByteBuffer input)
    throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeEncryptedContent is not implemented");
  }

  /**
   * Set the static default WireFormat used by default encoding and decoding
   * methods.
   * @param wireFormat An object of a subclass of WireFormat.  This does not
   * make a copy.
   */
  public static void
  setDefaultWireFormat(WireFormat wireFormat)
  {
    defaultWireFormat_ = wireFormat;
  }

  /**
   * Return the default WireFormat used by default encoding and decoding methods
   * which was set with setDefaultWireFormat.
   * @return The WireFormat object.
   */
  public static WireFormat
  getDefaultWireFormat()
  {
    return defaultWireFormat_;
  }

  private static WireFormat defaultWireFormat_ = TlvWireFormat.get();
}
