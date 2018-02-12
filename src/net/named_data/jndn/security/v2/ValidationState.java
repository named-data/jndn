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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.VerificationHelpers;
import net.named_data.jndn.util.Common;

/**
 * ValidationState is an abstract base class for DataValidationState and
 * InterestValidationState.
 *
 * One instance of the validation state is kept for the validation of the whole
 * certificate chain.
 *
 * The state collects the certificate chain that adheres to the selected
 * validation policy to validate data or interest packets. Certificate, data,
 * and interest packet signatures are verified only after the validator
 * determines that the chain terminates with a trusted certificate (a trusted
 * anchor or a previously validated certificate). This model allows filtering
 * out invalid certificate chains without incurring (costly) cryptographic
 * signature verification overhead and mitigates some forms of denial-of-service
 * attacks.
 *
 * A validation policy and/or key fetcher may add custom information associated
 * with the validation state using tags.
 */
public abstract class ValidationState {
  /**
   * Check if validation failed or success has been called.
   * @return True if validation failed or success has been called.
   */
  public final boolean
  hasOutcome() { return hasOutcome_; }

  /**
   * Check if validation failed has been called.
   * @return True if validation failed has been called, false if no validation
   * callbacks have been called or validation success was called.
   */
  public final boolean
  isOutcomeFailed() { return hasOutcome_ && outcome_ == false; }

  /**
   * Check if validation success has been called.
   * @return True if validation success has been called, false if no validation
   * callbacks have been called or validation failed was called.
   */
  public final boolean
  isOutcomeSuccess() { return hasOutcome_ && outcome_ == true; }

  /**
   * Call the failure callback.
   */
  public abstract void
  fail(ValidationError error);

  /**
   * Get the depth of the certificate chain.
   * @return The depth of the certificate chain.
   */
  public final int
  getDepth() { return certificateChain_.size(); }

  /**
   * Check if certificateName has been previously seen, and record the supplied
   * name.
   * @param certificateName The certificate name, which is copied.
   * @return True if certificateName has been previously seen.
   */
  public final boolean
  hasSeenCertificateName(Name certificateName)
  {
    if (seenCertificateNames_.contains(certificateName))
      return true;
    else {
      // Copy the Name.
      seenCertificateNames_.add(new Name(certificateName));
      return false;
    }
  }

  /**
   * Add the certificate to the top of the certificate chain.
   * If the certificate chain is empty, then the certificate should be the
   * signer of the original packet. If the certificate chain is not empty, then
   * the certificate should be the signer of the front of the certificate chain.
   * @note This function does not verify the signature bits.
   * @param certificate The certificate to add, which is copied.
   */
  public final void
  addCertificate(CertificateV2 certificate) throws CertificateV2.Error
  {
    certificateChain_.add(0, new CertificateV2(certificate));
  }

  /**
   * Set the outcome to the given value, and set hasOutcome_ true.
   * @param outcome The outcome.
   * @throws IllegalArgumentException If this ValidationState already has an
   * outcome.
   */
  protected final void
  setOutcome(boolean outcome)
  {
    if (hasOutcome_)
      throw new IllegalArgumentException
        ("The ValidationState already has an outcome");

    hasOutcome_ = true;
    outcome_ = outcome;
  }

  /**
   * Verify the signature of the original packet. This is only called by the
   * Validator class.
   * @param trustedCertificate The certificate that signs the original packet.
   */
  public abstract void
  verifyOriginalPacket_(CertificateV2 trustedCertificate);

  /**
   * Call the success callback of the original packet without signature
   * validation. This is only called by the Validator class.
   */
  public abstract void
  bypassValidation_();

  /**
   * Verify signatures of certificates in the certificate chain. On return, the
   * certificate chain contains a list of certificates successfully verified by
   * trustedCertificate.
   * When the certificate chain cannot be verified, this method will call
   * fail() with the INVALID_SIGNATURE error code and the appropriate message.
   * This is only called by the Validator class.
   * @return The certificate to validate the original data packet, either the
   * last entry in the certificate chain or trustedCertificate if the
   * certificate chain is empty. However, return null if the signature of at
   * least one certificate in the chain is invalid, in which case all unverified
   * certificates have been removed from the certificate chain.
   */
  public final CertificateV2
  verifyCertificateChain_(CertificateV2 trustedCertificate)
  {
    CertificateV2 validatedCertificate = trustedCertificate;
    for (int i = 0; i < certificateChain_.size(); ++i) {
      CertificateV2 certificateToValidate = certificateChain_.get(i);

      if (!VerificationHelpers.verifyDataSignature
          (certificateToValidate, validatedCertificate)) {
        fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
             "Invalid signature of certificate `" +
             certificateToValidate.getName().toUri() + "`"));
        // Remove this and remaining certificates in the chain.
        while (certificateChain_.size() > i)
          certificateChain_.remove(i);

        return null;
      }
      else {
        logger_.log(Level.FINE, "OK signature for certificate `{0}`",
                    certificateToValidate.getName().toUri());
        validatedCertificate = certificateToValidate;
      }
    }

    return validatedCertificate;
  }

  /**
   * Get the internal certificateChain_. This is only called by the Validator
   * class.
   * @return The internal certificateChain_.
   */
  public final ArrayList<CertificateV2>
  getCertificateChain_() { return certificateChain_; }

  /**
   * Each certificate in the chain signs the next certificate. The last
   * certificate signs the original packet.
   */
  private final ArrayList<CertificateV2> certificateChain_ =
    new ArrayList<CertificateV2>();
  private final HashSet<Name> seenCertificateNames_ = new HashSet<Name>();
  private boolean hasOutcome_ = false;
  private boolean outcome_;
  private static final Logger logger_ =
    Logger.getLogger(ValidationState.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
