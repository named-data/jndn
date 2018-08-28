/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-state.hpp
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

import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.security.VerificationHelpers;

/**
 * The DataValidationState class extends ValidationState to hold the validation
 * state for a Data packet.
 */
public class DataValidationState extends ValidationState {
  /**
   * Create a DataValidationState for the Data packet.
   * The caller must ensure that the state instance is valid until the validation
   * finishes (i.e., until validateCertificateChain() and
   * validateOriginalPacket() have been called).
   * @param data The Data packet being validated, which is copied.
   * @param successCallback This calls successCallback.successCallback(data) to
   * report a successful Data validation.
   * @param failureCallback This calls failureCallback.failureCallback(data, error)
   * to report a failed Data validation, where error is a ValidationError.
   */
  public DataValidationState
    (Data data, DataValidationSuccessCallback successCallback,
     DataValidationFailureCallback failureCallback)
  {
    // Make a copy.
    data_ = new Data(data);
    successCallback_ = successCallback;
    failureCallback_ = failureCallback;

    if (successCallback_ == null)
      throw new IllegalArgumentException("The successCallback is null");
    if (failureCallback_ == null)
      throw new IllegalArgumentException("The failureCallback is null");
  }

  public void
  fail(ValidationError error)
  {
    logger_.log(Level.FINE, "" + error);
    try {
      failureCallback_.failureCallback(data_, error);
    } catch (Throwable exception) {
      logger_.log(Level.SEVERE, "Error in failureCallback", exception);
    }
    setOutcome(false);
  }

  /**
   * Get the original Data packet being validated which was given to the
   * constructor.
   * @return The original Data packet.
   */
  public final Data
  getOriginalData() { return data_; }

  public void
  verifyOriginalPacket_(CertificateV2 trustedCertificate)
  {
    if (VerificationHelpers.verifyDataSignature(data_, trustedCertificate)) {
      logger_.log(Level.FINE,
        "OK signature for data `{0}`", data_.getName().toUri());
      try {
        successCallback_.successCallback(data_);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in successCallback", exception);
      }
      setOutcome(true);
    }
    else
      fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
        "Invalid signature of data `" + data_.getName().toUri() + "`"));
  }

  public void
  bypassValidation_()
  {
    logger_.log(Level.FINE, "Signature verification bypassed for data `{0}`",
                data_.getName().toUri());
    try {
      successCallback_.successCallback(data_);
    } catch (Throwable exception) {
      logger_.log(Level.SEVERE, "Error in successCallback", exception);
    }
    setOutcome(true);
  }

  private final Data data_;
  private final DataValidationSuccessCallback successCallback_;
  private final DataValidationFailureCallback failureCallback_;
  private static final Logger logger_ =
    Logger.getLogger(DataValidationState.class.getName());
}
