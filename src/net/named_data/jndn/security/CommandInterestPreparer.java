/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/command-interest-signer.cpp
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

package net.named_data.jndn.security;

import java.nio.ByteBuffer;
import net.named_data.jndn.Interest;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * A CommandInterestPreparer keeps track of a timestamp and prepares a command
 * interest by adding a timestamp and nonce to the name of an Interest. This
 * class is primarily designed to be used by the CommandInterestSigner, but can
 * also be using in an application that defines custom signing methods not
 * supported by the KeyChain (such as HMAC-SHA1). See the Command Interest
 * documentation:
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 */
public class CommandInterestPreparer {
  /**
   * Create a CommandInterestPreparer and initialize the timestamp to now.
   */
  public CommandInterestPreparer()
  {
    lastUsedTimestamp_ = Math.round(Common.getNowMilliseconds());
  }

  /**
   * Append a timestamp component and a random nonce component to interest's
   * name. This ensures that the timestamp is greater than the timestamp used in
   * the previous call.
   * @param interest The interest whose name is append with components.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo.
   */
  public void
  prepareCommandInterestName(Interest interest, WireFormat wireFormat)
  {
    double timestamp;
    synchronized(lastUsedTimestampLock_) {
      // nowOffsetMilliseconds_ is only used for testing.
      double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
      timestamp = Math.round(now);
      while (timestamp <= lastUsedTimestamp_)
        timestamp += 1.0;

      // Update the timestamp now while it is locked. In the small chance that
      //   signing fails, it just means that we have bumped the timestamp.
      lastUsedTimestamp_ = timestamp;
    }

    // The timestamp is encoded as a TLV nonNegativeInteger.
    TlvEncoder encoder = new TlvEncoder(8);
    encoder.writeNonNegativeInteger((long)timestamp);
    interest.getName().append(new Blob(encoder.getOutput(), false));

    // The random value is a TLV nonNegativeInteger too, but we know it is 8
    //   bytes, so we don't need to call the nonNegativeInteger encoder.
    ByteBuffer randomBuffer = ByteBuffer.allocate(8);
    // Note: SecureRandom is thread safe.
    Common.getRandom().nextBytes(randomBuffer.array());
    interest.getName().append(new Blob(randomBuffer, false));
  }

  /**
   * Append a timestamp component and a random nonce component to interest's
   * name. This ensures that the timestamp is greater than the timestamp used in
   * the previous call. Use the default WireFormat to encode the SignatureInfo.
   * @param interest The interest whose name is append with components.
   */
  public void
  prepareCommandInterestName(Interest interest)
  {
    prepareCommandInterestName(interest, WireFormat.getDefaultWireFormat());
  }

  /**
   * Set the offset for when prepareCommandInterestName() gets the current time,
   * which should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  public final void
  setNowOffsetMilliseconds_(double nowOffsetMilliseconds)
  {
    nowOffsetMilliseconds_ = nowOffsetMilliseconds;
  }

  private double lastUsedTimestamp_;
  private final Object lastUsedTimestampLock_ = new Object();
  private double nowOffsetMilliseconds_ = 0;
}
