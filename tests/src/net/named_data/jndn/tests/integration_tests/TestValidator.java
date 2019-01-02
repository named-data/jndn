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
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.ValidityPeriod;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.DataValidationFailureCallback;
import net.named_data.jndn.security.v2.DataValidationSuccessCallback;
import net.named_data.jndn.security.v2.TrustAnchorContainer;
import net.named_data.jndn.security.v2.ValidationError;
import net.named_data.jndn.security.v2.ValidationPolicy;
import net.named_data.jndn.security.v2.ValidationPolicySimpleHierarchy;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class TestValidator {
  HierarchicalValidatorFixture fixture_;

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
      (new ValidationPolicySimpleHierarchy());
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

  void
  makeCertificate(PibKey key, PibKey signer)
    throws CertificateV2.Error, Pib.Error, PibImpl.Error, TpmBackEnd.Error,
      KeyChain.Error
  {
    // Copy the default certificate.
    CertificateV2 request = new CertificateV2(key.getDefaultCertificate());
    request.setName(new Name(key.getName()).append("looper").appendVersion(1));

    // Set SigningInfo.
    SigningInfo params = new SigningInfo(signer);
    // Validity period from 100 days before to 100 days after now.
    double now = Common.getNowMilliseconds();
    params.setValidityPeriod(new ValidityPeriod
      (now - 100 * 24 * 3600 * 1000.0, now + 100 * 24 * 3600 * 1000.0));
    fixture_.keyChain_.sign(request, params);
    fixture_.keyChain_.addCertificate(key, request);

    fixture_.cache_.insert(request);
  }

  @Test
  public void
  testConstructorSetValidator()
  {
    Validator validator = fixture_.validator_;

    ValidationPolicy middlePolicy = new ValidationPolicySimpleHierarchy();
    ValidationPolicy innerPolicy = new ValidationPolicySimpleHierarchy();

    validator.getPolicy().setInnerPolicy(middlePolicy);
    validator.getPolicy().setInnerPolicy(innerPolicy);

    assertTrue(validator.getPolicy().getValidator_() != null);
    assertTrue(validator.getPolicy().getInnerPolicy().getValidator_() != null);
    assertTrue
      (validator.getPolicy().getInnerPolicy().getInnerPolicy().getValidator_() != null);
  }

  @Test
  public void
  testTimeouts()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    // Disable responses from the simulated Face.
    fixture_.face_.processInterest_ = null;

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    validateExpectFailure(data, "Should fail to retrieve certificate");
    // There should be multiple expressed interests due to retries.
    assertTrue(fixture_.face_.sentInterests_.size() > 1);
  }

  @Test
  public void
  testNackedInterests()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    fixture_.face_.processInterest_ = new ValidatorFixture.TestFace.ProcessInterest() {
      public void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack) {
        NetworkNack networkNack = new NetworkNack();
        networkNack.setReason(NetworkNack.Reason.NO_ROUTE);

        onNetworkNack.onNetworkNack(interest, networkNack);
      }
    };

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    validateExpectFailure(data, "All interests should get NACKed");
    // There should be multiple expressed interests due to retries.
    assertTrue(fixture_.face_.sentInterests_.size() > 1);
  }

  @Test
  public void
  testMalformedCertificate()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error, Pib.Error
  {
    // Copy the default certificate.
    final Data malformedCertificate = new Data
      (fixture_.subIdentity_.getDefaultKey().getDefaultCertificate());
    malformedCertificate.getMetaInfo().setType(ContentType.BLOB);
    fixture_.keyChain_.sign
      (malformedCertificate, new SigningInfo(fixture_.identity_));
    // It has the wrong content type and a missing ValidityPeriod.
    try {
      new CertificateV2(malformedCertificate).wireEncode();
      fail("Did not throw the expected exception");
    }
    catch (CertificateV2.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    final ValidatorFixture.TestFace.ProcessInterest originalProcessInterest =
      fixture_.face_.processInterest_;
    fixture_.face_.processInterest_ = new ValidatorFixture.TestFace.ProcessInterest() {
      public void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack) {
          if (interest.getName().isPrefixOf(malformedCertificate.getName()))
            onData.onData(interest, malformedCertificate);
          else
            originalProcessInterest.processInterest
              (interest, onData, onTimeout, onNetworkNack);
      }
    };

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    validateExpectFailure(data, "Signed by a malformed certificate");
    assertEquals(1, fixture_.face_.sentInterests_.size());
  }

  @Test
  public void
  testExpiredCertificate()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error, Pib.Error
  {
    // Copy the default certificate.
    final Data expiredCertificate = new Data
      (fixture_.subIdentity_.getDefaultKey().getDefaultCertificate());
    SigningInfo info = new SigningInfo(fixture_.identity_);
    // Validity period from 2 hours ago do 1 hour ago.
    double now = Common.getNowMilliseconds();
    info.setValidityPeriod
      (new ValidityPeriod(now - 2 * 3600 * 1000, now - 3600 * 1000.0));
    fixture_.keyChain_.sign(expiredCertificate, info);
    try {
      new CertificateV2(expiredCertificate).wireEncode();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    final ValidatorFixture.TestFace.ProcessInterest originalProcessInterest =
      fixture_.face_.processInterest_;
    fixture_.face_.processInterest_ = new ValidatorFixture.TestFace.ProcessInterest() {
      public void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack) {
          if (interest.getName().isPrefixOf(expiredCertificate.getName()))
            onData.onData(interest, expiredCertificate);
          else
            originalProcessInterest.processInterest
              (interest, onData, onTimeout, onNetworkNack);
      }
    };

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    validateExpectFailure(data, "Signed by an expired certificate");
    assertEquals(1, fixture_.face_.sentInterests_.size());
  }

  @Test
  public void
  testResetAnchors()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    fixture_.validator_.resetAnchors();

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));
    validateExpectFailure(data, "Should fail, as no anchors are configured");
  }

  @Test
  public void
  testTrustedCertificateCaching()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    validateExpectSuccess
      (data, "Should get accepted, as signed by the policy-compliant certificate");
    assertEquals(1, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    // Disable responses from the simulated Face.
    fixture_.face_.processInterest_ = null;

    validateExpectSuccess
      (data, "Should get accepted, based on the cached trusted certificate");
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    // Make the trusted cache simulate a time 2 hours later, after expiration.
    fixture_.validator_.setCacheNowOffsetMilliseconds_(2 * 3600 * 1000.0);

    validateExpectFailure(data, "Should try and fail to retrieve certificates");
    // There should be multiple expressed interests due to retries.
    assertTrue(fixture_.face_.sentInterests_.size() > 1);
    fixture_.face_.sentInterests_.clear();
  }

  @Test
  public void
  testResetVerifiedCertificates()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));
    validateExpectSuccess
      (data, "Should get accepted, as signed by the policy-compliant certificate");

    // Reset the anchors.
    fixture_.validator_.resetAnchors();
    validateExpectSuccess
      (data, "Should get accepted, as signed by the certificate in the trusted cache");

    // Reset the trusted cache.
    fixture_.validator_.resetVerifiedCertificates();
    validateExpectFailure
      (data, "Should fail, as there is no trusted cache or anchors");
  }

  @Test
  public void
  testUntrustedCertificateCaching()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subSelfSignedIdentity_));

    validateExpectFailure
      (data, "Should fail, as signed by the policy-violating certificate");
    assertEquals(1, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    validateExpectFailure
      (data, "Should fail again, but no network operations are expected");
    assertEquals(0, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    // Make the trusted cache simulate a time 20 minutes later, to expire the
    // untrusted cache (which has a lifetime of 5 minutes).
    fixture_.validator_.setCacheNowOffsetMilliseconds_(20 * 60 * 1000.0);

    // Disable responses from the simulated Face.
    fixture_.face_.processInterest_ = null;

    validateExpectFailure(data, "Should try and fail to retrieve certificates");
    assertTrue(fixture_.face_.sentInterests_.size() > 1);
    fixture_.face_.sentInterests_.clear();
  }

  @Test
  public void
  testInfiniteCertificateChain()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    fixture_.face_.processInterest_ = new ValidatorFixture.TestFace.ProcessInterest() {
      public void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack) {
        try {
          // Create another key for the same identity and sign it properly.
          PibKey parentKey =
            fixture_.keyChain_.createKey(fixture_.subIdentity_);
          PibKey requestedKey =
            fixture_.subIdentity_.getKey(interest.getName());

          // Copy the Name.
          Name certificateName = new Name(requestedKey.getName());
          certificateName.append("looper").appendVersion(1);
          CertificateV2 certificate = new CertificateV2();
          certificate.setName(certificateName);

          // Set the MetaInfo.
          certificate.getMetaInfo().setType(ContentType.KEY);
          // Set the freshness period to one hour.
          certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

          // Set the content.
          certificate.setContent(requestedKey.getPublicKey());

          // Set SigningInfo.
          SigningInfo params = new SigningInfo(parentKey);
          // Validity period from 10 days before to 10 days after now.
          double now = Common.getNowMilliseconds();
          params.setValidityPeriod(new ValidityPeriod
            (now - 10 * 24 * 3600 * 1000.0, now + 10 * 24 * 3600 * 1000.0));

          fixture_.keyChain_.sign(certificate, params);
          onData.onData(interest, certificate);
        } catch (Exception ex) {
          fail("Error in InfiniteCertificateChain: " + ex);
        }
      }
    };

    Data data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(fixture_.subIdentity_));

    fixture_.validator_.setMaxDepth(40);
    assertEquals(40, fixture_.validator_.getMaxDepth());
    validateExpectFailure(data, "Should fail since the certificate should be looped");
    assertEquals(40, fixture_.face_.sentInterests_.size());
    fixture_.face_.sentInterests_.clear();

    // Make the trusted cache simulate a time 5 hours later, after expiration.
    fixture_.validator_.setCacheNowOffsetMilliseconds_(5 * 3600 * 1000.0);

    fixture_.validator_.setMaxDepth(30);
    assertEquals(30, fixture_.validator_.getMaxDepth());
    validateExpectFailure(data, "Should fail since the certificate chain is infinite");
    assertEquals(30, fixture_.face_.sentInterests_.size());
  }

  @Test
  public void
  testLoopedCertificateChain()
    throws CertificateV2.Error, ValidatorConfigError, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error, Pib.Error, Tpm.Error
  {
    PibIdentity identity1 = fixture_.addIdentity(new Name("/loop"));
    PibKey key1 = fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key1")));
    PibKey key2 = fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key2")));
    PibKey key3 = fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key3")));

    makeCertificate(key1, key2);
    makeCertificate(key2, key3);
    makeCertificate(key3, key1);

    Data data = new Data(new Name("/loop/Data"));
    fixture_.keyChain_.sign(data, new SigningInfo(key1));
    validateExpectFailure(data, "Should fail since the certificate chain loops");
    assertEquals(3, fixture_.face_.sentInterests_.size());
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
