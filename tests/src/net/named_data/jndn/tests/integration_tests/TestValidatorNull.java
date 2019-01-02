/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validator-null.t.cpp
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
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.ValidatorNull;
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
import net.named_data.jndn.security.v2.ValidationError;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.fail;

public class TestValidatorNull {
  IdentityManagementFixture fixture_;

  @Before
  public void
  setUp() throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    fixture_ = new IdentityManagementFixture();
  }

  @Test
  public void
  testValidateData() 
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error, Pib.Error, 
      Tpm.Error, CertificateV2.Error, ValidatorConfigError
  {
    PibIdentity identity = fixture_.addIdentity(new Name("/TestValidator/Null"));
    Data data = new Data(new Name("/Some/Other/Data/Name"));
    fixture_.keyChain_.sign(data, new SigningInfo(identity));

    ValidatorNull validator = new ValidatorNull();
    validator.validate
      (data, new DataValidationSuccessCallback() {
        public void successCallback(Data data) {
          // Should succeed.
        }
      }, new DataValidationFailureCallback() {
        public void failureCallback(Data data, ValidationError error) {
          fail("Validation should not have failed");
        }
      });
  }

  @Test
  public void
  testValidateInterest()
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error, Pib.Error,
      Tpm.Error, CertificateV2.Error, ValidatorConfigError
  {
    PibIdentity identity = fixture_.addIdentity(new Name("/TestValidator/Null"));
    Interest interest = new Interest(new Name("/Some/Other/Interest/Name"));
    fixture_.keyChain_.sign(interest, new SigningInfo(identity));

    ValidatorNull validator = new ValidatorNull();
    validator.validate
      (interest, new InterestValidationSuccessCallback() {
        public void successCallback(Interest interest) {
          // Should succeed.
        }
      }, new InterestValidationFailureCallback() {
        public void failureCallback(Interest interest, ValidationError error) {
          fail("Validation should not have failed");
        }
      });
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
