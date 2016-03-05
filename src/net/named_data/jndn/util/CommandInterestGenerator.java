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

package net.named_data.jndn.util;

import java.nio.ByteBuffer;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;

/**
 * A CommandInterestGenerator keeps track of a timestamp and generates
 * command interests according to the NFD Signed Command Interests protocol:
 * http://redmine.named-data.net/projects/nfd/wiki/Command_Interests
 */
public class CommandInterestGenerator {
  /**
   * Create a new CommandInterestGenerator and initialize the timestamp to now.
   */
  public CommandInterestGenerator()
  {
    lastTimestamp_ = Math.round(Common.getNowMilliseconds());
  }

  /**
   * Append a timestamp component and a random value component to interest's
   * name. This ensures that the timestamp is greater than the timestamp used in
   * the previous call. Then use keyChain to sign the interest which appends a
   * SignatureInfo component and a component with the signature bits. If the
   * interest lifetime is not set, this sets it.
   * @param interest The interest whose name is append with components.
   * @param keyChain The KeyChain for calling sign.
   * @param certificateName The certificate name of the key to use for signing.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo and
   * to encode interest name for signing.
   */
  public void
  generate
    (Interest interest, KeyChain keyChain, Name certificateName,
     WireFormat wireFormat) throws SecurityException
  {
    double timestamp;
    synchronized(lastTimestampLock_) {
      timestamp = Math.round(Common.getNowMilliseconds());
      while (timestamp <= lastTimestamp_)
        timestamp += 1.0;
      // Update the timestamp now while it is locked. In the small chance that
      //   signing fails, it just means that we have bumped the timestamp.
      lastTimestamp_ = timestamp;
    }

    // The timestamp is encoded as a TLV nonNegativeInteger.
    TlvEncoder encoder = new TlvEncoder(8);
    encoder.writeNonNegativeInteger((long)timestamp);
    interest.getName().append(new Blob(encoder.getOutput(), false));

    // The random value is a TLV nonNegativeInteger too, but we know it is 8 bytes,
    //   so we don't need to call the nonNegativeInteger encoder.
    ByteBuffer randomBuffer = ByteBuffer.allocate(8);
    // Note: SecureRandom is thread safe.
    Common.getRandom().nextBytes(randomBuffer.array());
    interest.getName().append(new Blob(randomBuffer, false));

    keyChain.sign(interest, certificateName, wireFormat);

    if (interest.getInterestLifetimeMilliseconds() < 0)
      // The caller has not set the interest lifetime, so set it here.
      interest.setInterestLifetimeMilliseconds(1000.0);
  }

  /**
   * Append a timestamp component and a random value component to interest's
   * name. This ensures that the timestamp is greater than the timestamp used in
   * the previous call. Then use keyChain to sign the interest which appends a
   * SignatureInfo component and a component with the signature bits. If the
   * interest lifetime is not set, this sets it. Use the default WireFormat to
   * encode the SignatureInfo and to encode interest name for signing.
   * @param interest The interest whose name is append with components.
   * @param keyChain The KeyChain for calling sign.
   * @param certificateName The certificate name of the key to use for signing.
   */
  public void
  generate
    (Interest interest, KeyChain keyChain, Name certificateName) throws SecurityException
  {
    generate
      (interest, keyChain, certificateName, WireFormat.getDefaultWireFormat());
  }

  private double lastTimestamp_;
  private final Object lastTimestampLock_ = new Object();
}
