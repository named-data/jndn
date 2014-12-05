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
 * A ControlParameters holds a Name and other fields for a ControlParameters
 * which is used, for example, in the command interest to register a prefix with
 * a forwarder.
 */
public class ControlParameters {
  /**
   * Encode this ControlParameters for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this ControlParameters.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeControlParameters(this);
  }

  /**
   * Encode this ControlParameters for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this ControlParameters.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeControlParameters(this, input);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this ControlParameters.
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
   * Decode the input using a particular wire format and update this ControlParameters.
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
   * WireFormat.getDefaultWireFormat() and update this ControlParameters.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  public final Name
  getName() { return name_; }

  public final int
  getFaceId() { return faceId_; }
  
  public final String
  getUri() { return uri_; }

  public final int
  getLocalControlFeature() { return localControlFeature_; }

  public final int
  getOrigin() { return origin_; }

  public final int
  getCost() { return cost_; }

  public final ForwardingFlags
  getForwardingFlags() { return flags_; }

  public final Name
  getStrategy() { return strategy_; }
  
  public final double
  getExpirationPeriod() { return expirationPeriod_; }

  public final ControlParameters
  setName(Name name)
  {
    name_ = name == null ? new Name() : new Name(name);
    return this;
  }

  public final ControlParameters
  setFaceId(int faceId)
  {
    faceId_ = faceId;
    return this;
  }
  
  public final ControlParameters
  setUri(String uri)
  {
    uri_ = uri;
    return this;
  }

  public final ControlParameters
  setLocalControlFeature(int localControlFeature)
  {
    localControlFeature_ = localControlFeature;
    return this;
  }

  public final ControlParameters
  setOrigin(int origin)
  {
    origin_ = origin;
    return this;
  }

  public final ControlParameters
  setCost(int cost)
  {
    cost_ = cost;
    return this;
  }

  public final ControlParameters
  setForwardingFlags(ForwardingFlags forwardingFlags)
  {
    flags_ = forwardingFlags == null ?
      new ForwardingFlags() : new ForwardingFlags(forwardingFlags);
    return this;
  }
  
  public final ControlParameters
  setStrategy(Name strategy)
  {
    strategy_ = strategy;
    return this;
  }

  public final ControlParameters
  setExpirationPeriod(double expirationPeriod)
  {
    expirationPeriod_ = expirationPeriod;
    return this;
  }

  private Name name_;
  private int faceId_ = -1;                  /**< -1 for none. */
  private String uri_;
  private int localControlFeature_ = -1;     /**< -1 for none. */
  private int origin_ = -1;                  /**< -1 for none. */
  private int cost_ = -1;                    /**< -1 for none. */
  private ForwardingFlags flags_ = new ForwardingFlags();
  private Name strategy_;
  private double expirationPeriod_ = -1.0;   /**< Milliseconds. -1 for none. */
}
