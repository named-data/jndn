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

import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;

/**
 * CommandInterestSigner is a helper class to create command interests. This
 * keeps track of a timestamp and generates command interests by adding name
 * components according to the NFD Signed Command Interests protocol.
 * See makeCommandInterest() for details.
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 */
public class CommandInterestSigner extends CommandInterestPreparer {
  /**
   * Create a CommandInterestSigner to use the keyChain to sign.
   * @param keyChain The KeyChain used to sign.
   */
  public CommandInterestSigner(KeyChain keyChain)
  {
    keyChain_ = keyChain;
  }

  public static final int POS_SIGNATURE_VALUE = -1;
  public static final int POS_SIGNATURE_INFO =  -2;
  public static final int POS_NONCE =           -3;
  public static final int POS_TIMESTAMP =       -4;

  public static final int MINIMUM_SIZE = 4;

  /**
   * Append the timestamp and nonce name components to the supplied name, create
   * an Interest object and signs it with the KeyChain given to the constructor.
   * This ensures that the timestamp is greater than the timestamp used in the
   * previous call.
   * @param name The Name for the Interest, which is copied.
   * @param params The signing parameters.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo and
   * to encode interest name for signing.
   * @return A new command Interest object.
   */
  public final Interest
  makeCommandInterest(Name name, SigningInfo params, WireFormat wireFormat)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    // This copies the Name.
    Interest commandInterest = new Interest(name);

    prepareCommandInterestName(commandInterest, wireFormat);
    keyChain_.sign(commandInterest, params, wireFormat);

    return commandInterest;
  }

  /**
   * Call the main makeCommandInterest where wireFormat is
   * WireFormat.getDefaultWireFormat() .
   */
  public final Interest
  makeCommandInterest(Name name, SigningInfo params)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    return makeCommandInterest(name, params, WireFormat.getDefaultWireFormat());
  }

  /**
   * Call the main makeCommandInterest where the signing params is the default
   * SigningInfo() and wireFormat is WireFormat.getDefaultWireFormat() .
   */
  public final Interest
  makeCommandInterest(Name name)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    return makeCommandInterest
      (name, new SigningInfo(), WireFormat.getDefaultWireFormat());
  }

  private final KeyChain keyChain_;
}
