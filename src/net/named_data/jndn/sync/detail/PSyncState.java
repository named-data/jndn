/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/detail/state.cpp
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

package net.named_data.jndn.sync.detail;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.Tlv0_2WireFormat;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

/**
 * The PSyncState class represents a sequence of Names as the state of PSync.
 * It has methods to encode and decode for the wire.
 */
public class PSyncState {
  /**
   * Create a PSyncState with empty content.
   */
  public PSyncState() {}

  /**
   * Create a PSyncState by decoding the input as an NDN-TLV PSyncContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   */
  public PSyncState(ByteBuffer input) throws EncodingException
  {
    wireDecode(input);
  }

  /**
   * Create a PSyncState by decoding the input as an NDN-TLV PSyncContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   */
  public PSyncState(Blob input) throws EncodingException
  {
    wireDecode(input);
  }

  /**
   * Append the name to the content.
   * @param name The Name to add, which is copied.
   */
  public final void
  addContent(Name name) { content_.add(new Name(name)); }

  /**
   * Get the sequence of Names in the content.
   * @return The array of Names, which should not be modified.
   */
  public final ArrayList<Name>
  getContent() { return content_; }

  /**
   * Remove the content.
   */
  public final void
  clear() { content_.clear(); }

  /**
   * Encode this as an NDN-TLV PSyncContent.
   * @return The encoding as a Blob.
   */
  public final Blob
  wireEncode()
  {
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    for (int i = content_.size() - 1; i >= 0; --i)
      Tlv0_2WireFormat.encodeName(content_.get(i), new int[1], new int[1], encoder);

    encoder.writeTypeAndLength
      (Tlv_PSyncContent, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode the input as an NDN-TLV PSyncContent and update this object.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    clear();

    // Decode directly as TLV. We don't support the WireFormat abstraction
    // because this isn't meant to go directly on the wire.
    TlvDecoder decoder = new TlvDecoder(input);
    int endOffset = decoder.readNestedTlvsStart(Tlv_PSyncContent);

    // Decode a sequence of Name.
    while (decoder.getOffset() < endOffset) {
      Name name = new Name();
      Tlv0_2WireFormat.decodeName(name, new int[1], new int[1], decoder, true);
      content_.add(name);
    }

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Decode the input as an NDN-TLV PSyncContent and update this object.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  /**
   * Get the string representation of this PSyncState.
   * @return The string representation.
   */
  public String toString()
  {
    StringBuffer result = new StringBuffer();

    result.append("[");

    for (int i = 0; i < content_.size(); ++i) {
      result.append(content_.get(i).toUri());
      if (i < content_.size() - 1)
        result.append(", ");
    }

    result.append("]");

    return result.toString();
  }

  public static final int Tlv_PSyncContent = 128;

  private ArrayList<Name> content_ = new ArrayList<Name>();
}
