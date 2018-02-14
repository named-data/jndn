/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator.hpp
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
import net.named_data.jndn.Interest;
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * The Validator class provides an interface for validating data and interest
 * packets.
 *
 * Every time a validation process is initiated, it creates a ValidationState
 * that exists until the validation finishes with either success or failure.
 * This state serves several purposes:
 * to record the Interest or Data packet being validated,
 * to record the failure callback,
 * to record certificates in the certification chain for the Interest or Data
 * packet being validated,
 * to record the names of the requested certificates in order to detect loops in
 * the certificate chain,
 * and to keep track of the validation chain size (also known as the validation
 * "depth").
 *
 * During validation, the policy and/or key fetcher can augment the validation
 * state with policy- and fetcher-specific information using tags.
 *
 * A Validator has a trust anchor cache to save static and dynamic trust
 * anchors, a verified certificate cache for saving certificates that are
 * already verified, and an unverified certificate cache for saving pre-fetched
 * but not yet verified certificates.
 */
public class Validator extends CertificateStorage {
  /**
   * Create a Validator with the policy and fetcher.
   * @param policy The validation policy to be associated with this validator.
   * @param certificateFetcher The certificate fetcher implementation.
   */
  public Validator(ValidationPolicy policy, CertificateFetcher certificateFetcher)
  {
    policy_ = policy;
    certificateFetcher_ = certificateFetcher;
    maxDepth_ = 25;

    if (policy_ == null)
      throw new IllegalArgumentException("The policy is null");
    if (certificateFetcher_ == null)
      throw new IllegalArgumentException("The certificateFetcher is null");

    policy_.setValidator(this);
    certificateFetcher_.setCertificateStorage(this);
  }

  /**
   * Create a Validator with the policy. Use a CertificateFetcherOffline
   * (assuming that the validation policy doesn't need to fetch certificates).
   * @param policy The validation policy to be associated with this validator.
   */
  public Validator(ValidationPolicy policy)
  {
    policy_ = policy;
    certificateFetcher_ = new CertificateFetcherOffline();
    maxDepth_ = 25;

    if (policy_ == null)
      throw new IllegalArgumentException("The policy is null");

    policy_.setValidator(this);
    certificateFetcher_.setCertificateStorage(this);
  }

  /**
   * Get the ValidationPolicy given to the constructor.
   * @return The ValidationPolicy.
   */
  public final ValidationPolicy
  getPolicy() { return policy_; }

  /**
   * Get the CertificateFetcher given to (or created in) the constructor.
   * @return The CertificateFetcher.
   */
  public final CertificateFetcher
  getFetcher() { return certificateFetcher_; }

  /**
   * Set the maximum depth of the certificate chain.
   * @param maxDepth The maximum depth.
   */
  public final void
  setMaxDepth(int maxDepth) { maxDepth_ = maxDepth; }

  /**
   * Get the maximum depth of the certificate chain.
   * @return The maximum depth.
   */
  public final int
  getMaxDepth() { return maxDepth_; }

  /**
   * Asynchronously validate the Data packet.
   * @param data The Data packet to validate, which is copied.
   * @param successCallback On validation success, this calls
   * successCallback.successCallback(data).
   * @param failureCallback On validation failure, this calls
   * failureCallback.failureCallback(data, error) where error is a
   * ValidationError.
   */
  public final void
  validate
    (Data data, DataValidationSuccessCallback successCallback,
     DataValidationFailureCallback failureCallback)
    throws CertificateV2.Error, ValidatorConfigError
  {
    DataValidationState state =
      new DataValidationState(data, successCallback, failureCallback);
    logger_.log(Level.FINE, "Start validating data {0}", data.getName().toUri());

    policy_.checkPolicy
      (data, state, new ValidationPolicy.ValidationContinuation() {
        public void
        continueValidation
            (CertificateRequest certificateRequest, ValidationState state)
            throws CertificateV2.Error, ValidatorConfigError {
          if (certificateRequest == null)
            state.bypassValidation_();
          else
            // We need to fetch the key and validate it.
            requestCertificate(certificateRequest, state);
        }
      });
  }

  /**
   * Asynchronously validate the Interest.
   * @param interest The Interest to validate, which is copied.
   * @param successCallback On validation success, this calls
   * successCallback.successCallback(interest).
   * @param failureCallback On validation failure, this calls
   * failureCallback.failureCallback(interest, error) where error is a
   * ValidationError.
   */
  public final void
  validate
    (Interest interest, InterestValidationSuccessCallback successCallback,
     InterestValidationFailureCallback failureCallback)
    throws CertificateV2.Error, ValidatorConfigError
  {
    InterestValidationState state =
      new InterestValidationState(interest, successCallback, failureCallback);
    logger_.log(Level.FINE, "Start validating interest {0}",
      interest.getName().toUri());

    policy_.checkPolicy
      (interest, state, new ValidationPolicy.ValidationContinuation() {
        public void
        continueValidation
            (CertificateRequest certificateRequest, ValidationState state)
            throws CertificateV2.Error, ValidatorConfigError {
          if (certificateRequest == null)
            state.bypassValidation_();
          else
            // We need to fetch the key and validate it.
            requestCertificate(certificateRequest, state);
        }
      });
  }

  /**
   * Recursively validate the certificates in the certification chain.
   * @param certificate The certificate to check.
   * @param state The current validation state.
   */
  private void
  validateCertificate(final CertificateV2 certificate, ValidationState state)
    throws CertificateV2.Error, ValidatorConfigError
  {
    logger_.log(Level.FINE, "Start validating certificate {0}",
      certificate.getName().toUri());

    if (!certificate.isValid()) {
      state.fail(new ValidationError
        (ValidationError.EXPIRED_CERTIFICATE,
         "Retrieved certificate is not yet valid or expired `" +
         certificate.getName().toUri() + "`"));
      return;
    }

    policy_.checkCertificatePolicy
      (certificate, state, new ValidationPolicy.ValidationContinuation() {
        public void
        continueValidation
            (CertificateRequest certificateRequest, ValidationState state)
            throws CertificateV2.Error, ValidatorConfigError {
          if (certificateRequest == null)
            state.fail(new ValidationError
              (ValidationError.POLICY_ERROR,
               "Validation policy is not allowed to designate `" +
               certificate.getName().toUri() + "` as a trust anchor"));
          else {
            // We need to fetch the key and validate it.
            state.addCertificate(certificate);
            requestCertificate(certificateRequest, state);
          }
        }
      });
  }

  /**
   * Request a certificate for further validation.
   * @param certificateRequest The certificate request.
   * @param state The current validation state.
   */
  private void
  requestCertificate
    (CertificateRequest certificateRequest, ValidationState state)
    throws CertificateV2.Error, ValidatorConfigError
  {
    if (state.getDepth() >= maxDepth_) {
      state.fail(new ValidationError
        (ValidationError.EXCEEDED_DEPTH_LIMIT, "Exceeded validation depth limit"));
      return;
    }

    if (state.hasSeenCertificateName(certificateRequest.interest_.getName())) {
      state.fail(new ValidationError
        (ValidationError.LOOP_DETECTED,
         "Validation loop detected for certificate `" +
           certificateRequest.interest_.getName().toUri() + "`"));
      return;
    }

    logger_.log(Level.FINE, "Retrieving {0}",
      certificateRequest.interest_.getName().toUri());

    CertificateV2 certificate = findTrustedCertificate
      (certificateRequest.interest_);
    if (certificate != null) {
      logger_.log(Level.FINE, "Found trusted certificate {0}",
        certificate.getName().toUri());

      certificate = state.verifyCertificateChain_(certificate);
      if (certificate != null)
        state.verifyOriginalPacket_(certificate);

      for (int i = 0; i < state.getCertificateChain_().size(); ++i)
        cacheVerifiedCertificate(state.getCertificateChain_().get(i));

      return;
    }

    certificateFetcher_.fetch
      (certificateRequest, state, new CertificateFetcher.ValidationContinuation() {
        public void
        continueValidation(CertificateV2 certificate, ValidationState state)
            throws CertificateV2.Error, ValidatorConfigError {
          validateCertificate(certificate, state);
        }
      });
  }

  private final ValidationPolicy policy_;
  private final CertificateFetcher certificateFetcher_;
  private int maxDepth_;
  private static final Logger logger_ =
    Logger.getLogger(Validator.class.getName());
}
