/**
 * Copyright (C) 2015-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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

import java.io.File;
import java.io.IOException;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.ValidatorConfig;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.CertificateFetcher;
import net.named_data.jndn.security.v2.CertificateFetcherOffline;
import net.named_data.jndn.security.v2.CertificateRequest;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.DataValidationFailureCallback;
import net.named_data.jndn.security.v2.DataValidationState;
import net.named_data.jndn.security.v2.DataValidationSuccessCallback;
import net.named_data.jndn.security.v2.ValidationError;
import net.named_data.jndn.security.v2.ValidationPolicy;
import net.named_data.jndn.security.v2.ValidationState;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TestValidationPolicyConfig {
  static class TestValidationResult
    implements DataValidationSuccessCallback, DataValidationFailureCallback,
      ValidationPolicy.ValidationContinuation {
    /**
     * Create a TestValidationResult whose state_ will reference the given Data.
     * @param data The Data packed for the state_, which must remain valid.
     */
    public TestValidationResult(Data data)
    {
      data_ = data;
      reset();
    }

    /**
     * Reset all the results to false, to get ready for another result.
     */
    public final void
    reset()
    {
      state_ = new DataValidationState(data_, this, this);

      calledSuccess_ = false;
      calledFailure_ = false;
      calledContinue_ = false;
    }

    /**
     * Call reset() then call validator.checkPolicy to set this object's results.
     * When finished, you can check calledSuccess_, etc.
     * @param validator The ValidatorConfig for calling checkPolicy.
     */
    void
    checkPolicy(ValidatorConfig validator)
      throws CertificateV2.Error, ValidatorConfigError
    {
      reset();
      validator.getPolicy().checkPolicy(data_, state_, this);
    }

    public void
    successCallback(Data data)
    {
      calledSuccess_ = true;
    }

    public void
    failureCallback(Data data, ValidationError error)
    {
      calledFailure_ = true;
    }

    public void
    continueValidation
      (CertificateRequest certificateRequest, ValidationState state)
    {
      calledContinue_ = true;
    }

    public Data data_;
    public DataValidationState state_;
    public boolean calledSuccess_;
    public boolean calledFailure_;
    public boolean calledContinue_;
  }

  @Before
  public void
  setUp() throws SecurityException
  {
    policyConfigDirectory_ = IntegrationTestsCommon.getPolicyConfigDirectory();
  }

  File policyConfigDirectory_;

  @Test
  public void
  testNameRelation() throws IOException, ValidatorConfigError, CertificateV2.Error
  {
    // Set up the validators.
    CertificateFetcher fetcher = new CertificateFetcherOffline();
    ValidatorConfig validatorPrefix = new ValidatorConfig(fetcher);
    ValidatorConfig validatorEqual = new ValidatorConfig(fetcher);
    ValidatorConfig validatorStrict = new ValidatorConfig(fetcher);

    validatorPrefix.load
      (new File(policyConfigDirectory_, "relation_ruleset_prefix.conf").getAbsolutePath());
    validatorEqual.load
      (new File(policyConfigDirectory_, "relation_ruleset_equal.conf").getAbsolutePath());
    validatorStrict.load
      (new File(policyConfigDirectory_, "relation_ruleset_strict.conf").getAbsolutePath());

    // Set up a Data packet and result object.
    Data data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType
      (KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/KEY/123"));
    TestValidationResult result = new TestValidationResult(data);

    data.setName(new Name("/TestRule1"));
    result.checkPolicy(validatorPrefix);
    assertTrue("Prefix relation should match prefix name",
      result.calledContinue_ && !result.calledFailure_);
    result.checkPolicy(validatorEqual);
    assertTrue("Equal relation should match prefix name",
      result.calledContinue_ && !result.calledFailure_);
    result.checkPolicy(validatorStrict);
    assertTrue("Strict-prefix relation should not match prefix name",
      result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/TestRule1/hi"));
    result.checkPolicy(validatorPrefix);
    assertTrue("Prefix relation should match longer name",
      result.calledContinue_ && !result.calledFailure_);
    result.checkPolicy(validatorEqual);
    assertTrue("Equal relation should not match longer name",
      result.calledFailure_ && !result.calledContinue_);
    result.checkPolicy(validatorStrict);
    assertTrue("Strict-prefix relation should match longer name",
      result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/Bad/TestRule1/"));
    result.checkPolicy(validatorPrefix);
    assertTrue("Prefix relation should not match inner components",
      result.calledFailure_ && !result.calledContinue_);
    result.checkPolicy(validatorEqual);
    assertTrue("Equal relation should not match inner components",
      result.calledFailure_ && !result.calledContinue_);
    result.checkPolicy(validatorStrict);
    assertTrue("Strict-prefix relation should  not match inner components",
      result.calledFailure_ && !result.calledContinue_);
  }

  @Test
  public void
  testSimpleRegex() throws IOException, ValidatorConfigError, CertificateV2.Error
  {
    // Set up the validator.
    CertificateFetcher fetcher = new CertificateFetcherOffline();
    ValidatorConfig validator = new ValidatorConfig(fetcher);
    validator.load
      (new File(policyConfigDirectory_, "regex_ruleset.conf").getAbsolutePath());

    // Set up a Data packet and result object.
    Data data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/KEY/123"));
    TestValidationResult result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Basic/More"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Other/TestData"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/Basic/Data"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);
  }

  @Test
  public void
  testHierarchical() throws IOException, ValidatorConfigError, CertificateV2.Error
  {
    // Set up the validator.
    CertificateFetcher fetcher = new CertificateFetcherOffline();
    ValidatorConfig validator = new ValidatorConfig(fetcher);
    validator.load
      (new File(policyConfigDirectory_, "hierarchical_ruleset.conf").getAbsolutePath());

    // Set up a Data packet and result object.
    Data data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    TestValidationResult result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic/Data1"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));

    data.setName(new Name("/SecurityTestSecRule/Basic/Data1"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));
    result.checkPolicy(validator);
    assertTrue(result.calledContinue_ && !result.calledFailure_);
  }

  @Test
  public void
  testHyperRelation() throws IOException, ValidatorConfigError, CertificateV2.Error
  {
    // Set up the validator.
    CertificateFetcher fetcher = new CertificateFetcherOffline();
    ValidatorConfig validator = new ValidatorConfig(fetcher);
    validator.load
      (new File(policyConfigDirectory_, "hyperrelation_ruleset.conf").getAbsolutePath());

    // Set up a Data packet and result object.
    Data data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    TestValidationResult result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Other/Data1"));

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));
    result.checkPolicy(validator);
    assertTrue(result.calledFailure_ && !result.calledContinue_);
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
