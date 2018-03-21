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
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * CommandInterestSigner is a helper class to create command interests. This
 * keeps track of a timestamp and generates command interests by adding name
 * components according to the NFD Signed Command Interests protocol.
 * See makeCommandInterest() for details.
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 */
public class CommandInterestSigner {
  /**
   * Create a CommandInterestSigner to use the keyChain to sign.
   * @param keyChain The KeyChain used to sign.
   */
  public CommandInterestSigner(KeyChain keyChain)
  {
    keyChain_ = keyChain;
    lastUsedTimestamp_ = Math.round(Common.getNowMilliseconds());
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
    commandInterest.getName().append(new Blob(encoder.getOutput(), false));

    // The random value is a TLV nonNegativeInteger too, but we know it is 8 bytes,
    //   so we don't need to call the nonNegativeInteger encoder.
    ByteBuffer randomBuffer = ByteBuffer.allocate(8);
    // Note: SecureRandom is thread safe.
    Common.getRandom().nextBytes(randomBuffer.array());
    commandInterest.getName().append(new Blob(randomBuffer, false));

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

  /**
   * Set the offset for when makeCommandInterest() gets the current time, which
   * should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  public final void
  setNowOffsetMilliseconds_(double nowOffsetMilliseconds)
  {
    nowOffsetMilliseconds_ = nowOffsetMilliseconds;
  }

  private final KeyChain keyChain_;
  private double lastUsedTimestamp_;
  private final Object lastUsedTimestampLock_ = new Object();
  private double nowOffsetMilliseconds_ = 0;
}
