/**
 * Copyright (C) 2016-2020 Regents of the University of California.
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
import net.named_data.jndn.Interest;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

/**
 * A Tlv0_2WireFormat implements the WireFormat interface for encoding and
 * decoding with the NDN-TLV wire format, version 0.2.
 */
public class Tlv0_2WireFormat extends Tlv0_3WireFormat {
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
    if (!interest.getDidSetCanBePrefix_() && !didCanBePrefixWarning_) {
      System.out.println
        ("WARNING: The default CanBePrefix will change. See Interest.setDefaultCanBePrefix() for details.");
      didCanBePrefixWarning_ = true;
    }

    if (interest.hasApplicationParameters())
      // The application has specified a format v0.3 field. As we transition to
      // format v0.3, encode as format v0.3 even though the application default
      // is Tlv0_2WireFormat.
      return encodeInterestV03
        (interest, signedPortionBeginOffset, signedPortionEndOffset);

    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    if (interest.getForwardingHint().size() > 0) {
      if (interest.getSelectedDelegationIndex() >= 0)
        throw new Error
          ("An Interest may not have a selected delegation when encoding a forwarding hint");
      if (interest.hasLink())
        throw new Error
          ("An Interest may not have a link object when encoding a forwarding hint");

      int forwardingHintSaveLength = encoder.getLength();
      encodeDelegationSet(interest.getForwardingHint(), encoder);
      encoder.writeTypeAndLength
        (Tlv.ForwardingHint, encoder.getLength() - forwardingHintSaveLength);
    }

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
   * Get a singleton instance of a Tlv0_2WireFormat.  To always use the
   * preferred version NDN-TLV, you should use TlvWireFormat.get().
   * @return The singleton instance.
   */
  public static Tlv0_2WireFormat
  get()
  {
    return instance_;
  }

  private static final Random random_ = new Random();
  private static Tlv0_2WireFormat instance_ = new Tlv0_2WireFormat();
}
