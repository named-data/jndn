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

import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibKey;

/**
 * ValidationPolicyFromPib extends ValidationPolicy to implement a validator
 * policy that validates a packet using the default certificate of the key in
 * the PIB that is named by the packet's KeyLocator.
 */
public class ValidationPolicyFromPib extends ValidationPolicy {
  /**
   * Create a ValidationPolicyFromPib to use the given PIB.
   * @param pib The PIB with certificates.
   */
  public ValidationPolicyFromPib(Pib pib)
  {
    pib_ = pib;
  }

  public void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    Name keyName = getKeyLocatorName(data, state);
    if (state.isOutcomeFailed())
      // Already called state.fail() .
      return;

    checkPolicyHelper(keyName, state, continueValidation);
  }

  public void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    Name keyName = getKeyLocatorName(interest, state);
    if (state.isOutcomeFailed())
      // Already called state.fail() .
      return;

    checkPolicyHelper(keyName, state, continueValidation);
  }

  private void
  checkPolicyHelper
    (Name keyName, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    PibIdentity identity;
    try {
      identity = pib_.getIdentity(PibKey.extractIdentityFromKeyName(keyName));
    } catch (Throwable ex) {
      state.fail(new ValidationError
        (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
         "Cannot get the PIB identity for key " + keyName.toUri() + ": " + ex));
      return;
    }

    PibKey key;
    try {
      key = identity.getKey(keyName);
    } catch (Throwable ex) {
      state.fail(new ValidationError
        (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
         "Cannot get the PIB key " + keyName.toUri() + ": " + ex));
      return;
    }

    CertificateV2 certificate;
    try {
      certificate = key.getDefaultCertificate();
    } catch (Throwable ex) {
      state.fail(new ValidationError
        (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
         "Cannot get the default certificate for key " + keyName.toUri() + ": " +
         ex));
      return;
    }

    // Add the certificate as the temporary trust anchor.
    validator_.resetAnchors();
    try {
      validator_.loadAnchor("", certificate);
    } catch (Throwable ex) {
      // We don't expect this since we just retrieved the certificate.
      state.fail(new ValidationError
        (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
         "Cannot load the trust anchor for key " + keyName.toUri() + ": " +
         ex));
      return;
    }

    continueValidation.continueValidation
      (new CertificateRequest(new Interest(keyName)), state);
    // Clear the temporary trust anchor.
    validator_.resetAnchors();
  }

  private final Pib pib_;
}
