/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/identity-management-fixture.cpp
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

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidityPeriod;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public class IdentityManagementFixture {
  public IdentityManagementFixture()
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    keyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
  }

  public final boolean
  saveCertificateToFile(Data data, String filePath)
  {
    certificateFiles_.add(filePath);

    try {
      Blob encoding = data.wireEncode();
      String encodedCertificate = Common.base64Encode
        (encoding.getImmutableArray(), true);

      BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
      // Use "try/finally instead of "try-with-resources" or "using"
      // which are not supported before Java 7.
      try {
        writer.write(encodedCertificate, 0, encodedCertificate.length());
        writer.flush();
      }
      finally{
        writer.close();
      }

      return true;
    }
    catch (Exception ex) {
      return false;
    }
  }

  /**
   * Add an identity for the identityName.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the
   * identity.
   * @return The created PibIdentity instance.
   */
  public final PibIdentity
  addIdentity(Name identityName, KeyParams params)
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, KeyChain.Error
  {
    PibIdentity identity = keyChain_.createIdentityV2(identityName, params);
    identityNames_.add(identityName);
    return identity;
  }

  /**
   * Add an identity for the identityName.
   * Use KeyChain.getDefaultKeyParams().
   * @param identityName The name of the identity.
   * @return The created PibIdentity instance.
   */
  public final PibIdentity
  addIdentity(Name identityName)
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, KeyChain.Error
  {
    return addIdentity(identityName, KeyChain.getDefaultKeyParams());
  }

  /**
   *  Save the identity's certificate to a file.
   *  @param identity The PibIdentity.
   *  @param filePath The file path, which should be writable.
   *  @return True if successful.
   */
  public final boolean
  saveCertificate(PibIdentity identity, String filePath) throws PibImpl.Error
  {
    try {
      CertificateV2 certificate =
        identity.getDefaultKey().getDefaultCertificate();
      return saveCertificateToFile(certificate, filePath);
    }
    catch (Pib.Error ex) {
      return false;
    }
  }

  /**
   * Issue a certificate for subIdentityName signed by issuer. If the identity
   * does not exist, it is created. A new key is generated as the default key
   * for the identity. A default certificate for the key is signed by the
   * issuer using its default certificate.
   * @param subIdentityName The name to issue the certificate for.
   * @param issuer The identity of the signer.
   * @param params The key parameters if a key needs to be generated for the
   * identity.
   * @return The sub identity.
   */
  PibIdentity
  addSubCertificate
    (Name subIdentityName, PibIdentity issuer, KeyParams params)
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error, Pib.Error,
      CertificateV2.Error, Tpm.Error
  {
    PibIdentity subIdentity = addIdentity(subIdentityName, params);

    CertificateV2 request = subIdentity.getDefaultKey().getDefaultCertificate();

    request.setName(request.getKeyName().append("parent").appendVersion(1));

    SigningInfo certificateParams = new SigningInfo(issuer);
    // Validity period of 20 years.
    double now = Common.getNowMilliseconds();
    certificateParams.setValidityPeriod
      (new ValidityPeriod(now, now + 20 * 365 * 24 * 3600 * 1000.0));

    // Skip the AdditionalDescription.

    keyChain_.sign(request, certificateParams);
    keyChain_.setDefaultCertificate(subIdentity.getDefaultKey(), request);

    return subIdentity;
  }

  /**
   * Issue a certificate for subIdentityName signed by issuer. If the identity
   * does not exist, it is created. A new key is generated as the default key
   * for the identity. A default certificate for the key is signed by the
   * issuer using its default certificate.
   * Use KeyChain.getDefaultKeyParams().
   * @param subIdentityName The name to issue the certificate for.
   * @param issuer The identity of the signer.
   * @return The sub identity.
   */
  PibIdentity
  addSubCertificate(Name subIdentityName, PibIdentity issuer)
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error, Pib.Error,
      CertificateV2.Error, Tpm.Error
  {
    return addSubCertificate
      (subIdentityName, issuer, KeyChain.getDefaultKeyParams());
  }

  /**
   * Add a self-signed certificate made from the key and issuer ID.
   * @param key The key for the certificate.
   * @param issuerId The issuer ID name component for the certificate name.
   * @return The new certificate.
   */
  CertificateV2
  addCertificate(PibKey key, String issuerId)
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    Name certificateName = new Name(key.getName());
    certificateName.append(issuerId).appendVersion(3);
    CertificateV2 certificate = new CertificateV2();
    certificate.setName(certificateName);

    // Set the MetaInfo.
    certificate.getMetaInfo().setType(ContentType.KEY);
    // One hour.
    certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.);

    // Set the content.
    certificate.setContent(key.getPublicKey());

    SigningInfo params = new SigningInfo(key);
    // Validity period of 10 days.
    double now = Common.getNowMilliseconds();
    params.setValidityPeriod
      (new ValidityPeriod(now, now + 10 * 24 * 3600 * 1000.0));

    keyChain_.sign(certificate, params);
    return certificate;
  }

  public KeyChain keyChain_;

  private HashSet<Name> identityNames_ = new HashSet<Name>();
  private HashSet<String> certificateFiles_ = new HashSet<String>();
}
