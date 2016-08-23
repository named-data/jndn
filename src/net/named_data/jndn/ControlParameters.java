/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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
 *
 * Note: getters will never be null so check for empty Names with something like
 * `controlParameters.getStrategy().size() != 0`
 */
public class ControlParameters {
  /**
   * Create a new ControlParameters where all values are unspecified.
   */
  public
  ControlParameters() {}

  /**
   * Create a new ControlParameters as a deep copy of the given controlParameters.
   * @param controlParameters The ControlParameters to copy.
   */
  public
  ControlParameters(ControlParameters controlParameters)
  {
    name_ = controlParameters.name_ == null ?
      null : new Name(controlParameters.name_);
    faceId_ = controlParameters.faceId_;
    uri_ = controlParameters.uri_;
    localControlFeature_ = controlParameters.localControlFeature_;
    origin_ = controlParameters.origin_;
    cost_ = controlParameters.cost_;
    flags_ = new ForwardingFlags(controlParameters.flags_);
    strategy_ = new Name(controlParameters.strategy_);
    expirationPeriod_ = controlParameters.expirationPeriod_;
  }

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
    wireFormat.decodeControlParameters(this, input, true);
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
    wireFormat.decodeControlParameters(this, input.buf(), false);
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

  /**
   * Get the name.
   * @return The Name. If not specified, return null.
   */
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

  /**
   * Set the name.
   * @param name The name. If not specified, set to null. If specified, this
   * makes a copy of the name.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setName(Name name)
  {
    name_ = name == null ? null : new Name(name);
    return this;
  }

  /**
   * Set the Face ID.
   * @param faceId The new face ID, or -1 for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setFaceId(int faceId)
  {
    faceId_ = faceId;
    return this;
  }

  /**
   * Set the URI.
   * @param uri The new uri, or an empty string for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setUri(String uri)
  {
    uri_ = uri == null ? "" : uri;
    return this;
  }

  /**
   * Set the local control feature value.
   * @param localControlFeature The new local control feature value, or -1 for
   * not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setLocalControlFeature(int localControlFeature)
  {
    localControlFeature_ = localControlFeature;
    return this;
  }

  /**
   * Set the origin value.
   * @param origin The new origin value, or -1 for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setOrigin(int origin)
  {
    origin_ = origin;
    return this;
  }

  /**
   * Set the cost value.
   * @param cost The new cost value, or -1 for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setCost(int cost)
  {
    cost_ = cost;
    return this;
  }

  /**
   * Set the ForwardingFlags object to a copy of forwardingFlags. You can use
   * getForwardingFlags() and change the existing ForwardingFlags object.
   * @param forwardingFlags The new cost value, or null for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setForwardingFlags(ForwardingFlags forwardingFlags)
  {
    flags_ = forwardingFlags == null ?
      new ForwardingFlags() : new ForwardingFlags(forwardingFlags);
    return this;
  }

  /**
   * Set the strategy to a copy of the given Name.
   * @param strategy The Name to copy, or an empty Name if not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setStrategy(Name strategy)
  {
    strategy_ = strategy == null ? new Name() : new Name(strategy);
    return this;
  }

  /**
   * Set the expiration period.
   * @param expirationPeriod The expiration period in milliseconds, or
   * null for not specified.
   * @return This ControlParameters so that you can chain calls to update values.
   */
  public final ControlParameters
  setExpirationPeriod(double expirationPeriod)
  {
    expirationPeriod_ = expirationPeriod;
    return this;
  }

  /**
   * Clear fields and reset to default values.
   */
  public final void
  clear()
  {
    name_ = null;
    faceId_ = -1;
    uri_ = "";
    localControlFeature_ = -1;
    origin_ = -1;
    cost_ = -1;
    flags_ = new ForwardingFlags();
    strategy_ = new Name();
    expirationPeriod_ = -1.0;
  }

  public boolean
  equals(Object other)
  {
    return false;
  }

  private Name name_ = null;
  private int faceId_ = -1;                  /**< -1 for none. */
  private String uri_ = "";
  private int localControlFeature_ = -1;     /**< -1 for none. */
  private int origin_ = -1;                  /**< -1 for none. */
  private int cost_ = -1;                    /**< -1 for none. */
  private ForwardingFlags flags_ = new ForwardingFlags();
  private Name strategy_ = new Name();
  private double expirationPeriod_ = -1.0;   /**< Milliseconds. -1 for none. */
}
