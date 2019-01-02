/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validation-policy-command-interest.t.cpp
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
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.security.CommandInterestSigner;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
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
import net.named_data.jndn.security.v2.ValidationPolicyCommandInterest;
import net.named_data.jndn.security.v2.ValidationPolicySimpleHierarchy;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.fail;

class ValidationPolicyCommandInterestFixture extends HierarchicalValidatorFixture {
  public ValidationPolicyCommandInterestFixture
    (ValidationPolicyCommandInterest.Options options)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
      CertificateV2.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error,
      TrustAnchorContainer.Error
  {
    super(new ValidationPolicyCommandInterest
      (new ValidationPolicySimpleHierarchy(), options));
    signer_ = new CommandInterestSigner(keyChain_);
  }

  public ValidationPolicyCommandInterestFixture()
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
      CertificateV2.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error,
      TrustAnchorContainer.Error
  {
    super(new ValidationPolicyCommandInterest(new ValidationPolicySimpleHierarchy()));
    signer_ = new CommandInterestSigner(keyChain_);
  }

  Interest
  makeCommandInterest(PibIdentity identity)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    return signer_.makeCommandInterest
      (new Name(identity.getName()).append("CMD"), new SigningInfo(identity));
  }

  /**
   * Set the offset for the validation policy and signer.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  void
  setNowOffsetMilliseconds(double nowOffsetMilliseconds)
  {
    ((ValidationPolicyCommandInterest)validator_.getPolicy()).setNowOffsetMilliseconds_
       (nowOffsetMilliseconds);
    validator_.setCacheNowOffsetMilliseconds_(nowOffsetMilliseconds);
    signer_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
  }

  public CommandInterestSigner signer_;
}

public class TestValidationPolicyCommandInterest {
  ValidationPolicyCommandInterestFixture fixture_;

  @Before
  public void
  setUp() throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
    CertificateV2.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error,
    TrustAnchorContainer.Error
  {
    // Turn off INFO log messages.
    Logger.getLogger("").setLevel(Level.SEVERE);

    fixture_ = new ValidationPolicyCommandInterestFixture();
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

  static void
  setNameComponent(Interest interest, int index, Name.Component component)
  {
    Name name = interest.getName().getPrefix(index);
    name.append(component);
    name.append(interest.getName().getSubName(name.size()));
    interest.setName(name);
  }

  static void
  setNameComponent(Interest interest, int index, String component)
  {
    setNameComponent(interest, index, new Name.Component(component));
  }

  static void
  setNameComponent(Interest interest, int index, Blob component)
  {
    setNameComponent(interest, index, new Name.Component(component));
  }

  @Test
  public void
  testBasic() throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error,
    CertificateV2.Error, ValidatorConfigError
  {
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest1, "Should succeed (within grace period)");

    fixture_.setNowOffsetMilliseconds(5 * 1000.0);
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest2, "Should succeed (timestamp larger than previous)");
  }

  @Test
  public void
  testDataPassthrough() throws SecurityException, TpmBackEnd.Error,
    PibImpl.Error, KeyChain.Error, CertificateV2.Error, ValidatorConfigError
  {
    Data data1 = new Data(new Name("/Security/V2/ValidatorFixture/Sub1"));
    fixture_.keyChain_.sign(data1);
    validateExpectSuccess(data1,
      "Should succeed (fallback on inner validation policy for data)");
  }

  @Test
  public void
  testNameTooShort() throws CertificateV2.Error, ValidatorConfigError
  {
    Interest interest1 = new Interest(new Name("/name/too/short"));
    validateExpectFailure(interest1, "Should fail (name is too short)");
  }

  @Test
  public void
  testBadSignatureInfo() throws CertificateV2.Error, ValidatorConfigError,
    PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Interest interest1;
    interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO, "not-SignatureInfo");
    validateExpectFailure(interest1, "Should fail (missing signature info)");
  }

  @Test
  public void
  testMissingKeyLocator() throws CertificateV2.Error, ValidatorConfigError,
    PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    Sha256WithRsaSignature signatureInfo = new Sha256WithRsaSignature();
    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    validateExpectFailure(interest1, "Should fail (missing KeyLocator)");
  }

  @Test
  public void
  testBadKeyLocatorType() throws CertificateV2.Error, ValidatorConfigError,
    PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(new Blob(new int[]
      { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd }));
    Sha256WithRsaSignature signatureInfo = new Sha256WithRsaSignature();
    signatureInfo.setKeyLocator(keyLocator);

    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    validateExpectFailure(interest1, "Should fail (bad KeyLocator type)");
  }

  @Test
  public void
  testBadCertificateName() throws CertificateV2.Error, ValidatorConfigError,
    PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(new Name("/bad/cert/name"));
    Sha256WithRsaSignature signatureInfo = new Sha256WithRsaSignature();
    signatureInfo.setKeyLocator(keyLocator);

    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    validateExpectFailure(interest1, "Should fail (bad certificate name)");
  }

  @Test
  public void
  testInnerPolicyReject() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError
  {
    Interest interest1 = fixture_.makeCommandInterest(fixture_.otherIdentity_);
    validateExpectFailure(interest1, "Should fail (inner policy should reject)");
  }

  @Test
  public void
  testTimestampOutOfGracePositive() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0));

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Verifying at +16 seconds.
    fixture_.setNowOffsetMilliseconds(16 * 1000.0);
    validateExpectFailure(interest1,
      "Should fail (timestamp outside the grace period)");

    // Signed at +16 seconds.
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest2, "Should succeed");
  }

  @Test
  public void
  testTimestampOutOfGraceNegative() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0));

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +1 seconds.
    fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +2 seconds.
    fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    Interest interest3 = fixture_.makeCommandInterest(fixture_.identity_);

    // Verifying at -16 seconds.
    fixture_.setNowOffsetMilliseconds(-16 * 1000.0);
    validateExpectFailure(interest1,
      "Should fail (timestamp outside the grace period)");

    // The CommandInterestValidator should not remember interest1's timestamp.
    validateExpectFailure(interest2,
      "Should fail (timestamp outside the grace period)");

    // The CommandInterestValidator should not remember interest2's timestamp, and
    // should treat interest3 as initial.
    // Verifying at +2 seconds.
    fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    validateExpectSuccess(interest3, "Should succeed");
  }

  @Test
  public void
  testTimestampReorderEqual() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest1, "Should succeed");

    // Signed at 0 seconds.
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    setNameComponent
      (interest2, CommandInterestSigner.POS_TIMESTAMP,
       interest1.getName().get(CommandInterestSigner.POS_TIMESTAMP));
    validateExpectFailure(interest2, "Should fail (timestamp reordered)");

    // Signed at +2 seconds.
    fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    Interest interest3 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest3, "Should succeed");
  }

  @Test
  public void
  testTimestampReorderNegative() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    // Signed at 0 seconds.
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +200 milliseconds.
    fixture_.setNowOffsetMilliseconds(200.0);
    Interest interest3 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +1100 milliseconds.
    fixture_.setNowOffsetMilliseconds(1100.0);
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +1400 milliseconds.
    fixture_.setNowOffsetMilliseconds(1400.0);
    Interest interest4 = fixture_.makeCommandInterest(fixture_.identity_);

    // Verifying at +1100 milliseconds.
    fixture_.setNowOffsetMilliseconds(1100.0);
    validateExpectSuccess(interest1, "Should succeed");

    // Verifying at 0 milliseconds.
    fixture_.setNowOffsetMilliseconds(0.0);
    validateExpectFailure(interest2, "Should fail (timestamp reordered)");

    // The CommandInterestValidator should not remember interest2's timestamp.
    // Verifying at +200 milliseconds.
    fixture_.setNowOffsetMilliseconds(200.0);
    validateExpectFailure(interest3, "Should fail (timestamp reordered)");

    // Verifying at +1400 milliseconds.
    fixture_.setNowOffsetMilliseconds(1400.0);
    validateExpectSuccess(interest4, "Should succeed");
  }

  @Test
  public void
  testLimitedRecords() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 3));

    PibIdentity identity1 = fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub1"), fixture_.identity_);
    fixture_.cache_.insert(identity1.getDefaultKey().getDefaultCertificate());
    PibIdentity identity2 = fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub2"), fixture_.identity_);
    fixture_.cache_.insert(identity2.getDefaultKey().getDefaultCertificate());
    PibIdentity identity3 = fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub3"), fixture_.identity_);
    fixture_.cache_.insert(identity3.getDefaultKey().getDefaultCertificate());
    PibIdentity identity4 = fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub4"), fixture_.identity_);
    fixture_.cache_.insert(identity4.getDefaultKey().getDefaultCertificate());

    Interest interest1 = fixture_.makeCommandInterest(identity2);
    Interest interest2 = fixture_.makeCommandInterest(identity3);
    Interest interest3 = fixture_.makeCommandInterest(identity4);
    // Signed at 0 seconds.
    Interest interest00 = fixture_.makeCommandInterest(identity1);
    // Signed at +1 seconds.
    fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    Interest interest01 = fixture_.makeCommandInterest(identity1);
    // Signed at +2 seconds.
    fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    Interest interest02 = fixture_.makeCommandInterest(identity1);

    validateExpectSuccess(interest00, "Should succeed");

    validateExpectSuccess(interest02, "Should succeed");

    validateExpectSuccess(interest1, "Should succeed");

    validateExpectSuccess(interest2, "Should succeed");

    validateExpectSuccess(interest3, "Should succeed, forgets identity1");

    validateExpectSuccess(interest01,
      "Should succeed despite timestamp is reordered, because the record has been evicted");
  }

  @Test
  public void
  testUnlimitedRecords() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, -1));

    ArrayList<PibIdentity> identities = new ArrayList<PibIdentity>();
    for (int i = 0; i < 20; ++i) {
      PibIdentity identity = fixture_.addSubCertificate
        (new Name("/Security/V2/ValidatorFixture/Sub" + i), fixture_.identity_);
      fixture_.cache_.insert(identity.getDefaultKey().getDefaultCertificate());
      identities.add(identity);
    }

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(identities.get(0));
    fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    for (int i = 0; i < 20; ++i) {
      // Signed at +1 seconds.
      Interest interest2 = fixture_.makeCommandInterest(identities.get(i));

      validateExpectSuccess(interest2, "Should succeed");
    }

    validateExpectFailure(interest1, "Should fail (timestamp reorder)");
  }

  @Test
  public void
  testZeroRecords() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 0));

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +1 seconds.
    fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest2, "Should succeed");

    validateExpectSuccess(interest1,
      "Should succeed despite the timestamp being reordered, because the record isn't kept");
  }

  @Test
  public void
  testLimitedRecordLifetime() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(400 * 1000.0, 1000, 300 * 1000.0));

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +240 seconds.
    fixture_.setNowOffsetMilliseconds(240 * 1000.0);
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +360 seconds.
    fixture_.setNowOffsetMilliseconds(360 * 1000.0);
    Interest interest3 = fixture_.makeCommandInterest(fixture_.identity_);

    // Validate at 0 seconds.
    fixture_.setNowOffsetMilliseconds(0.0);
    validateExpectSuccess(interest1, "Should succeed");

    validateExpectSuccess(interest3, "Should succeed");

    // Validate at +301 seconds.
    fixture_.setNowOffsetMilliseconds(301 * 1000.0);
    validateExpectSuccess(interest2,
      "Should succeed despite the timestamp being reordered, because the record has expired");
  }

  @Test
  public void
  testZeroRecordLifetime() throws PibImpl.Error, KeyChain.Error,
    TpmBackEnd.Error, CertificateV2.Error, ValidatorConfigError,
    SecurityException, IOException, Pib.Error, Tpm.Error,
    TrustAnchorContainer.Error
  {
    fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 1000, 0.0));

    // Signed at 0 seconds.
    Interest interest1 = fixture_.makeCommandInterest(fixture_.identity_);
    // Signed at +1 second.
    fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    Interest interest2 = fixture_.makeCommandInterest(fixture_.identity_);
    validateExpectSuccess(interest2, "Should succeed");

    validateExpectSuccess(interest1,
      "Should succeed despite the timestamp being reordered, because the record has expired");
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
