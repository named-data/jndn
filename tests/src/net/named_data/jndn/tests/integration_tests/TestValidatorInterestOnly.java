/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/validator.t.cpp
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

package src.net.named_data.jndn.tests.integration_tests;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.DataValidationFailureCallback;
import net.named_data.jndn.security.v2.DataValidationSuccessCallback;
import net.named_data.jndn.security.v2.InterestValidationFailureCallback;
import net.named_data.jndn.security.v2.InterestValidationSuccessCallback;
import net.named_data.jndn.security.v2.TrustAnchorContainer;
import net.named_data.jndn.security.v2.ValidationError;
import net.named_data.jndn.security.v2.ValidationPolicySimpleHierarchy;
import net.named_data.jndn.security.v2.ValidationState;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertEquals;

public class TestValidatorInterestOnly {
  HierarchicalValidatorFixture fixture_;

  static class ValidationPolicySimpleHierarchyForInterestOnly extends
      ValidationPolicySimpleHierarchy {
    public void
    checkPolicy
      (Data data, ValidationState state, ValidationContinuation continueValidation)
        throws CertificateV2.Error, ValidatorConfigError
    {
      continueValidation.continueValidation(null, state);
    }
  }

  @Before
  public void
  setUp()
    throws KeyChain.Error, PibImpl.Error, net.named_data.jndn.security.SecurityException, IOException,
      CertificateV2.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error,
      TrustAnchorContainer.Error
  {
    // Turn off INFO log messages.
    Logger.getLogger("").setLevel(Level.SEVERE);

    fixture_ = new HierarchicalValidatorFixture
      (new ValidationPolicySimpleHierarchyForInterestOnly());
  }

  /**
   * Call fixture_.validator_.validate and if it calls the failureCallback then
   * fail the test with the given message.
   * @param data The Data to validate.
   * @param message The message to show if the test fails.
   */
  void
  validateExpectSuccess(Data data, final String message)
    throws CertificateV2.Error, ValidatorConfigError
  {
    fixture_.validator_.validate
      (data,
       new DataValidationSuccessCallback() {
        public void successCallback(Data data) {
        }
       },
       new DataValidationFailureCallback() {
        public void failureCallback(Data data, ValidationError error) {
          fail(message);
        }
       });
  }

  /**
   * Call fixture_.validator_.validate and if it calls the successCallback then
   * fail the test with the given message.
   * @param data The Data to validate.
   * @param message The message to show if the test succeeds.
   */
  void
  validateExpectFailure(Data data, final String message)
    throws CertificateV2.Error, ValidatorConfigError
  {
    fixture_.validator_.validate
      (data,
      new DataValidationSuccessCallback() {
        public void successCallback(Data data) {
          fail(message);
        }
      },
      new DataValidationFailureCallback() {
        public void failureCallback(Data data, ValidationError error) {
        }
      });
  }

  /**
   * Call fixture_.validator_.validate and if it calls the failureCallback then
   * fail the test with the given message.
   * @param interest The Interest to validate.
   * @param message The message to show if the test fails.
   */
  void
  validateExpectSuccess(Interest interest, final String message)
    throws CertificateV2.Error, ValidatorConfigError
  {
    fixture_.validator_.validate
      (interest,
       new InterestValidationSuccessCallback() {
        public void successCallback(Interest interest) {
        }
       },
       new InterestValidationFailureCallback() {
        public void failureCallback(Interest interest, ValidationError error) {
          fail(message);
        }
       });
  }

  /**
   * Call fixture_.validator_.validate and if it calls the successCallback then
   * fail the test with the given message.
   * @param interest The Interest to validate.
   * @param message The message to show if the test succeeds.
   */
  void
  validateExpectFailure(Interest interest, final String message)
    throws CertificateV2.Error, ValidatorConfigError
  {
    fixture_.validator_.validate
      (interest,
      new InterestValidationSuccessCallback() {
        public void successCallback(Interest interest) {
          fail(message);
        }
      },
      new InterestValidationFailureCallback() {
        public void failureCallback(Interest interest, ValidationError error) {
        }
      });
  }

  @Test
  public void
  testValidateInterestsButBypassForData()
    throws CertificateV2.Error, ValidatorConfigError, PibImpl.Error,
      KeyChain.Error, TpmBackEnd.Error
  {
    Interest interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    Data data = new Data
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));

    validateExpectFailure(interest, "Unsigned");
    validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    fixture_.keyChain_.sign
      (interest, new SigningInfo(SigningInfo.SignerType.SHA256));
    fixture_.keyChain_.sign
      (data, new SigningInfo(SigningInfo.SignerType.SHA256));
    validateExpectFailure(interest,
      "Required KeyLocator/Name is missing (not passed to the policy)");
    validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    fixture_.keyChain_.sign(interest, new SigningInfo(fixture_.identity_));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.identity_));
    validateExpectSuccess(interest,
      "Should be successful since it is signed by the anchor");
    validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    fixture_.keyChain_.sign(interest, new SigningInfo(fixture_.subIdentity_));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));
    validateExpectFailure(interest,
      "Should fail since the policy is not allowed to create new trust anchors");
    validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assertEquals(1, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    fixture_.keyChain_.sign(interest, new SigningInfo(fixture_.otherIdentity_));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.otherIdentity_));
    validateExpectFailure(interest,
      "Should fail since it is signed by a policy-violating certificate");
    validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    // No network operations are expected since the certificate is not validated
    // by the policy.
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    // Make the trusted cache simulate a time 2 hours later, after expiration.
    fixture_.validator_.setCacheNowOffsetMilliseconds_(2 * 3600 * 1000.0);

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    fixture_.keyChain_.sign(interest, new SigningInfo(fixture_.subSelfSignedIdentity_));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subSelfSignedIdentity_));
    validateExpectFailure(interest,
     "Should fail since the policy is not allowed to create new trust anchors");
    validateExpectSuccess(data, "The policy requests to bypass validation for all data");
    assertEquals(1, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
