/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.CommandInterestPreparer;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;

/**
 * A CommandInterestGenerator keeps track of a timestamp and generates
 * command interests according to the NFD Signed Command Interests protocol:
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 */
public class CommandInterestGenerator extends CommandInterestPreparer {
  /**
   * Create a new CommandInterestGenerator and initialize the timestamp to now.
   */
  public CommandInterestGenerator()
  {
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
    prepareCommandInterestName(interest, wireFormat);
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
}
