/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.policy;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifiedInterest;
import net.named_data.jndn.security.OnDataValidationFailed;
import net.named_data.jndn.security.OnInterestValidationFailed;
import net.named_data.jndn.security.ValidationRequest;

/**
 *
 */
public class NoVerifyPolicyManager extends PolicyManager {
  /**
   * Override to always skip verification and trust as valid.
   * @param data The received data packet.
   * @return true.
   */
  public final boolean skipVerifyAndTrust(Data data)
  {
    return true;
  }

  /**
   * Override to always skip verification and trust as valid.
   * @param interest The received interest.
   * @return true.
   */
  public final boolean skipVerifyAndTrust(Interest interest)
  {
    return true;
  }

  /**
   * Override to return false for no verification rule for the received data.
   * @param data The received data packet.
   * @return false.
   */
  public final boolean requireVerify(Data data)
  {
    return false;
  }

  /**
   * Override to return false for no verification rule for the received interest.
   * @param interest The received interest.
   * @return false.
   */
  public final boolean requireVerify(Interest interest)
  {
    return false;
  }

  /**
   * Override to call onVerified.onVerified(data) and to indicate no further
   * verification step.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
   * @param onVerified This does override to call onVerified.onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed Override to ignore this.
   * @return null for no further step.
   */
  public final ValidationRequest checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified,
     OnDataValidationFailed onValidationFailed)
    throws SecurityException
  {
    try {
      onVerified.onVerified(data);
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onVerified", ex);
    }
    return null;
  }

  /**
   * Override to call onVerified.onVerifiedInterest(interest) and to indicate no
   * further verification step.
   * @param interest The interest with the signature (to ignore).
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
   * @param onVerified This does override to call onVerified.onVerifiedInterest(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed Override to ignore this.
   * @return null for no further step.
   */
  public final ValidationRequest checkVerificationPolicy
    (Interest interest, int stepCount, OnVerifiedInterest onVerified,
     OnInterestValidationFailed onValidationFailed, WireFormat wireFormat)
    throws SecurityException
  {
    try {
      onVerified.onVerifiedInterest(interest);
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onVerifiedInterest", ex);
    }
    return null;
  }

  /**
   * Override to always indicate that the signing certificate name and data name
   * satisfy the signing policy.
   * @param dataName The name of data to be signed.
   * @param certificateName The name of signing certificate.
   * @return true to indicate that the signing certificate can be used to sign
   * the data.
   */
  public final boolean checkSigningPolicy(Name dataName, Name certificateName)
  {
    return true;
  }

  /**
   * Override to indicate that the signing identity cannot be inferred.
   * @param dataName The name of data to be signed.
   * @return An empty name because cannot infer.
   */
  public final Name inferSigningIdentity(Name dataName)
  {
    return new Name();
  }

  private static final Logger logger_ = Logger.getLogger
    (NoVerifyPolicyManager.class.getName());
}
