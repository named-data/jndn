/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

package net.named_data.jndn.security.v2;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Interest;
import net.named_data.jndn.security.VerificationHelpers;
import net.named_data.jndn.util.Common;

/**
 * The InterestValidationState class extends ValidationState to hold the
 * validation state for an Interest packet.
 */
public class InterestValidationState extends ValidationState {
  /**
   * Create an InterestValidationState for the Data packet.
   * The caller must ensure that the state instance is valid until the validation
   * finishes (i.e., until validateCertificateChain() and
   * validateOriginalPacket() have been called).
   * @param interest The Interest packet being validated, which is copied.
   * @param successCallback This calls successCallback.successCallback(interest)
   * to report a successful Interest validation.
   * @param failureCallback This calls
   * failureCallback.failureCallback(interest, error) to report a failed
   * Interest validation, where error is a ValidationError.
   */
  public InterestValidationState
    (Interest interest, InterestValidationSuccessCallback successCallback,
     InterestValidationFailureCallback failureCallback)
  {
    // Make a copy.
    interest_ = new Interest(interest);
    successCallbacks_.add(successCallback);
    failureCallback_ = failureCallback;

    if (successCallback == null)
      throw new IllegalArgumentException("The successCallback is null");
    if (failureCallback_ == null)
      throw new IllegalArgumentException("The failureCallback is null");
  }

  public void
  fail(ValidationError error)
  {
    logger_.log(Level.FINE, "" + error);
    try {
      failureCallback_.failureCallback(interest_, error);
    } catch (Throwable exception) {
      logger_.log(Level.SEVERE, "Error in failureCallback", exception);
    }
    setOutcome(false);
  }

  /**
   * Get the original Interest packet being validated which was given to the
   * constructor.
   * @return The original Interest packet.
   */
  public final Interest
  getOriginalInterest() { return interest_; }

  public final void
  addSuccessCallback(InterestValidationSuccessCallback successCallback)
  {
    successCallbacks_.add(successCallback);
  }

  public void
  verifyOriginalPacket_(CertificateV2 trustedCertificate)
  {
    if (VerificationHelpers.verifyInterestSignature(interest_, trustedCertificate)) {
      logger_.log(Level.FINE,
        "OK signature for interest `{0}`", interest_.getName().toUri());
      for (int i = 0; i < successCallbacks_.size(); ++i) {
        try {
          successCallbacks_.get(i).successCallback(interest_);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in successCallback", exception);
        }
      }
      setOutcome(true);
    }
    else
      fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
        "Invalid signature of interest `" + interest_.getName().toUri() + "`"));
  }

  public void
  bypassValidation_()
  {
    logger_.log(Level.FINE, "Signature verification bypassed for interest `{0}`",
                interest_.getName().toUri());
    for (int i = 0; i < successCallbacks_.size(); ++i) {
      try {
        successCallbacks_.get(i).successCallback(interest_);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in successCallback", exception);
      }
    }
    setOutcome(true);
  }

  private final Interest interest_;
  private final ArrayList<InterestValidationSuccessCallback> successCallbacks_ =
    new ArrayList<InterestValidationSuccessCallback>();
  private final InterestValidationFailureCallback failureCallback_;
  private static final Logger logger_ =
    Logger.getLogger(InterestValidationState.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
