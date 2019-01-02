/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/validator-fixture.cpp
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
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.ValidationPolicy;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.TrustAnchorContainer;

public class HierarchicalValidatorFixture extends ValidatorFixture {
  public HierarchicalValidatorFixture(ValidationPolicy policy)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
      CertificateV2.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error,
      TrustAnchorContainer.Error
  {
    super(policy);

    identity_ = addIdentity(new Name("/Security/V2/ValidatorFixture"));
    subIdentity_ = addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub1"), identity_);
    subSelfSignedIdentity_ = addIdentity
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2"));
    otherIdentity_ = addIdentity(new Name("/Security/V2/OtherIdentity"));

    validator_.loadAnchor
      ("", new CertificateV2(identity_.getDefaultKey().getDefaultCertificate()));

    cache_.insert(identity_.getDefaultKey().getDefaultCertificate());
    cache_.insert(subIdentity_.getDefaultKey().getDefaultCertificate());
    cache_.insert(subSelfSignedIdentity_.getDefaultKey().getDefaultCertificate());
    cache_.insert(otherIdentity_.getDefaultKey().getDefaultCertificate());
  }

  public final PibIdentity identity_;
  public final PibIdentity subIdentity_;
  public final PibIdentity subSelfSignedIdentity_;
  public final PibIdentity otherIdentity_;
}
