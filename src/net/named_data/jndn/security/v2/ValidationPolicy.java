/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy.hpp
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
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * ValidationPolicy is an abstract base class that implements a validation
 * policy for Data and Interest packets.
 */
public abstract class ValidationPolicy {
  public interface ValidationContinuation {
    void
    continueValidation
      (CertificateRequest certificateRequest, ValidationState state)
      throws CertificateV2.Error, ValidatorConfigError;
  }

  /**
   * Set the inner policy.
   * Multiple assignments of the inner policy will create a "chain" of linked
   * policies. The inner policy from the latest invocation of setInnerPolicy
   * will be at the bottom of the policy list.
   * For example, the sequence `this.setInnerPolicy(policy1)` and
   * `this.setInnerPolicy(policy2)`, will result in
   * `this.innerPolicy_ == policy1`,
   * this.innerPolicy_.innerPolicy_ == policy2', and
   * `this.innerPolicy_.innerPolicy_.innerPolicy_ == null`.
   * @throws IllegalArgumentException if the innerPolicy is null.
   */
  public final void
  setInnerPolicy(ValidationPolicy innerPolicy)
  {
    if (innerPolicy == null)
      throw new IllegalArgumentException
        ("The innerPolicy argument cannot be null");

    if (validator_ != null)
      innerPolicy.setValidator(validator_);

    if (innerPolicy_ == null)
      innerPolicy_ = innerPolicy;
    else
      innerPolicy_.setInnerPolicy(innerPolicy);
  }

  /**
   * Check if the inner policy is set.
   * @return True if the inner policy is set.
   */
  public final boolean
  hasInnerPolicy() { return innerPolicy_ != null; }

  /**
   * Get the inner policy. If the inner policy was not set, the behavior is
   * undefined.
   * @return The inner policy.
   */
  public final ValidationPolicy
  getInnerPolicy() { return innerPolicy_; }

  /**
   * Set the validator to which this policy is associated. This replaces any
   * previous validator.
   * @param validator The validator.
   */
  public final void
  setValidator(Validator validator)
  {
    validator_ = validator;
    if (innerPolicy_ != null)
      innerPolicy_.setValidator(validator);
  }

  /**
   * Check the Data packet against the policy.
   * Your derived class must implement this.
   * Depending on the implementation of the policy, this check can be done
   * synchronously or asynchronously.
   * The semantics of checkPolicy are as follows:
   * If the packet violates the policy, then the policy should call
   * state.fail() with an appropriate error code and error description.
   * If the packet conforms to the policy and no further key retrievals are
   * necessary, then the policy should call
   * continueValidation.continueValidation(null, state).
   * If the packet conforms to the policy and a key needs to be fetched, then
   * the policy should call
   * continueValidation.continueValidation({appropriate-key-request-instance}, state).
   * @param data The Data packet to check.
   * @param state The ValidationState of this validation.
   * @param continueValidation The policy should call
   * continueValidation.continueValidation() as described above.
   */
  public abstract void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError;

  /**
   * Check the Interest against the policy.
   * Your derived class must implement this.
   * Depending on implementation of the policy, this check can be done
   * synchronously or asynchronously.
   * See the checkPolicy(Data) documentation for the semantics.
   * @param interest The Interest packet to check.
   * @param state The ValidationState of this validation.
   * @param continueValidation The policy should call
   * continueValidation.continueValidation() as described above.
   */
  public abstract void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError;

  /**
   * Check the certificate against the policy.
   * This base class implementation just calls checkPolicy(Data, ...). Your
   * derived class may override.
   * Depending on implementation of the policy, this check can be done
   * synchronously or asynchronously.
   * See the checkPolicy(Data) documentation for the semantics.
   * @param certificate The certificate to check.
   * @param state The ValidationState of this validation.
   * @param continueValidation The policy should call continueValidation() as
   * described above.
   */
  public void
  checkCertificatePolicy
    (CertificateV2 certificate, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    checkPolicy(certificate, state, continueValidation);
  }

  /** Extract the KeyLocator Name from a Data packet.
   * The Data packet must contain a KeyLocator of type KEYNAME.
   * Otherwise, state.fail is invoked with INVALID_KEY_LOCATOR.
   * @param data The Data packet with the KeyLocator.
   * @param state On error, this calls state.fail and returns an empty Name.
   * @return The KeyLocator name, or an empty Name for failure.
   */
  public static Name
  getKeyLocatorName(Data data, ValidationState state)
  {
    return getKeyLocatorNameFromSignature(data.getSignature(), state);
  }

  /**
   * Extract the KeyLocator Name from a signed Interest.
   * The Interest must have SignatureInfo and contain a KeyLocator of type
   * KEYNAME. Otherwise, state.fail is invoked with INVALID_KEY_LOCATOR.
   * @param interest The signed Interest with the KeyLocator.
   * @param state On error, this calls state.fail and returns an empty Name.
   * @return The KeyLocator name, or an empty Name for failure.
   */
  public static Name
  getKeyLocatorName(Interest interest, ValidationState state)
  {
    Name name = interest.getName();
    if (name.size() < 2) {
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Invalid signed Interest: name too short"));
      return new Name();
    }

    Signature signatureInfo;
    try {
      // TODO: Generalize the WireFormat.
      signatureInfo =
        WireFormat.getDefaultWireFormat().decodeSignatureInfoAndValue
        (interest.getName().get(-2).getValue().buf(),
         interest.getName().get(-1).getValue().buf());
    } catch (Throwable ex) {
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Invalid signed Interest: " + ex));
      return new Name();
    }

    return getKeyLocatorNameFromSignature(signatureInfo, state);
  }

  /**
   * A helper method for getKeyLocatorName.
   */
  private static Name
  getKeyLocatorNameFromSignature
    (Signature signatureInfo, ValidationState state)
  {
    if (!KeyLocator.canGetFromSignature(signatureInfo)) {
      state.fail(new ValidationError
        (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator is missing"));
      return new Name();
    }

    KeyLocator keyLocator = KeyLocator.getFromSignature(signatureInfo);
    if (keyLocator.getType() != KeyLocatorType.KEYNAME) {
      state.fail(new ValidationError
        (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator type is not Name"));
      return new Name();
    }

    return keyLocator.getKeyName();
  }

  /**
   * Get the validator_ field, used only for testing.
   */
  public final Validator getValidator_() { return validator_; }

  protected Validator validator_ = null;
  protected ValidationPolicy innerPolicy_ = null;
}
