/**
 * Copyright (C) 2015 Regents of the University of California.
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

package net.named_data.jndn;

import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;

/**
 * A LocalControlHeader represents an NFD LocalControlHeader which holds fields
 * like face ID. A LocalControlHeader object is optional in an Interest or Data
 * object.
 */
public class LocalControlHeader {
  /**
   * Create a LocalControlHeader where all fields are not specified.
   */
  public LocalControlHeader() {}

  /**
   * Create a LocalControlHeader with a copy of the fields in localControlHeader.
   * @param localControlHeader The LocalControlHeader to copy.
   */
  public LocalControlHeader(LocalControlHeader localControlHeader)
  {
    incomingFaceId_ = localControlHeader.incomingFaceId_;
    nextHopFaceId_ = localControlHeader.nextHopFaceId_;
    payloadWireEncoding_ = localControlHeader.payloadWireEncoding_;
  }

  /**
   * Get the incoming face ID.
   * @return The incoming face ID. If not specified, return -1.
   */
  public long
  getIncomingFaceId() { return incomingFaceId_; }

  /**
   * Get the next hop face ID.
   * @return The next hop face ID. If not specified, return -1.
   */
  public long
  getNextHopFaceId() { return nextHopFaceId_; }

  public Blob
  getPayloadWireEncoding() { return payloadWireEncoding_; }

  /**
   * Set the incoming face ID.
   * @param incomingFaceId The incoming face ID. If not specified, set to -1.
   */
  public void
  setIncomingFaceId(long incomingFaceId) { incomingFaceId_ = incomingFaceId; }

  /**
   * Set the next hop face ID.
   * @param nextHopFaceId The next hop face ID. If not specified, set to -1.
   */
  public void
  setNextHopFaceId(long nextHopFaceId) { nextHopFaceId_ = nextHopFaceId; }

  public void
  setPayloadWireEncoding(Blob payloadWireEncoding)
  {
    payloadWireEncoding_ =
      (payloadWireEncoding == null ? new Blob() : payloadWireEncoding);
  }

  /**
   * Encode this LocalControlHeader for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this LocalControlHeader.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeLocalControlHeader(this);
  }

  /**
   * Encode this LocalControlHeader for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this LocalControlHeader.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeLocalControlHeader(this, input);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this LocalControlHeader.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this LocalControlHeader.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireDecode(input.buf(), wireFormat);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this LocalControlHeader.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }


  private long incomingFaceId_ = -1;
  private long nextHopFaceId_ = -1;
  private Blob payloadWireEncoding_ = new Blob();
  // For now, ignore CachingPolicy since it for the LocalControlHeader in a Data
  // packet from the application to NFD, and for now we only support a
  // LocalControlHeader in the Interest packet from the application.
}
