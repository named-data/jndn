/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn;

import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;

/**
 * A ForwardingEntry holds an action and Name prefix and other fields for a
 * forwarding entry.
 */
public class ForwardingEntry {

  public final String
  getAction() { return action_; }

  public final Name
  getPrefix() { return prefix_; }

  public final PublisherPublicKeyDigest
  getPublisherPublicKeyDigest() { return publisherPublicKeyDigest_; }

  public final int
  getFaceId() { return faceId_; }

  public final ForwardingFlags
  getForwardingFlags() { return forwardingFlags_; }

  public final double
  getFreshnessPeriod() { return freshnessPeriod_; }

  public final void
  setAction(String action) { action_ = action == null ? "" : action; }

  public final void
  setPrefix(Name prefix)
  {
    prefix_ = prefix == null ? new Name() : new Name(prefix);
  }

  public final void
  setFaceId(int faceId) { faceId_ = faceId; }

  public final void
  setForwardingFlags(ForwardingFlags forwardingFlags)
  {
    forwardingFlags_ = forwardingFlags == null ?
      new ForwardingFlags() : new ForwardingFlags(forwardingFlags);
  }

  public final void
  setFreshnessPeriod(double freshnessPeriod)
  {
    freshnessPeriod_ = freshnessPeriod;
  }

  /**
   * Encode this ForwardingEntry for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this ForwardingEntry.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeForwardingEntry(this);
  }

  /**
   * Encode this ForwardingEntry for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this ForwardingEntry.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeForwardingEntry(this, input);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this ForwardingEntry.
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
   * Decode the input using a particular wire format and update this ForwardingEntry.
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
   * WireFormat.getDefaultWireFormat() and update this ForwardingEntry.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  private String action_ = ""; /**< "" for none. */
  private Name prefix_ = new Name();
  private PublisherPublicKeyDigest publisherPublicKeyDigest_ =
    new PublisherPublicKeyDigest();
  private int faceId_ = -1; /**< -1 for none. */
  private ForwardingFlags forwardingFlags_ = new ForwardingFlags();
  private double freshnessPeriod_ = -1.0; /**< Milliseconds. -1 for none. */
}
