/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/signing-info.t.cpp
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

package net.named_data.jndn.tests.unit_tests;

import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestSigningInfo {
  @Test
  public void
  testBasic()
  {
    Name identityName = new Name("/my-identity");
    Name keyName = new Name("/my-key");
    Name certificateName = new Name("/my-cert");

    SigningInfo info = new SigningInfo();

    assertEquals(SigningInfo.SignerType.NULL, info.getSignerType());
    assertTrue(new Name().equals(info.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    info.setSigningIdentity(identityName);
    assertEquals(SigningInfo.SignerType.ID, info.getSignerType());
    assertTrue(identityName.equals(info.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    SigningInfo infoId = new SigningInfo(SigningInfo.SignerType.ID, identityName);
    assertEquals(SigningInfo.SignerType.ID, infoId.getSignerType());
    assertTrue(identityName.equals(infoId.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm());

    info.setSigningKeyName(keyName);
    assertEquals(SigningInfo.SignerType.KEY, info.getSignerType());
    assertTrue(keyName.equals(info.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    SigningInfo infoKey = new SigningInfo(SigningInfo.SignerType.KEY, keyName);
    assertEquals(SigningInfo.SignerType.KEY, infoKey.getSignerType());
    assertTrue(keyName.equals(infoKey.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm());

    info.setSigningCertificateName(certificateName);
    assertEquals(SigningInfo.SignerType.CERT, info.getSignerType());
    assertTrue(certificateName.equals(info.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    SigningInfo infoCert = new SigningInfo
      (SigningInfo.SignerType.CERT, certificateName);
    assertEquals(SigningInfo.SignerType.CERT, infoCert.getSignerType());
    assertTrue(certificateName.equals(infoCert.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm());

    info.setSha256Signing();
    assertEquals(SigningInfo.SignerType.SHA256, info.getSignerType());
    assertTrue(new Name().equals(info.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    SigningInfo infoSha256 = new SigningInfo(SigningInfo.SignerType.SHA256);
    assertEquals(SigningInfo.SignerType.SHA256, infoSha256.getSignerType());
    assertTrue(new Name().equals(infoSha256.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoSha256.getDigestAlgorithm());
  }

  @Test
  public void
  testFromString()
  {
    SigningInfo infoDefault = new SigningInfo("");
    assertEquals(SigningInfo.SignerType.NULL, infoDefault.getSignerType());
    assertTrue(new Name().equals(infoDefault.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoDefault.getDigestAlgorithm());

    SigningInfo infoId = new SigningInfo("id:/my-identity");
    assertEquals(SigningInfo.SignerType.ID, infoId.getSignerType());
    assertTrue(new Name("/my-identity").equals(infoId.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm());

    SigningInfo infoKey = new SigningInfo("key:/my-key");
    assertEquals(SigningInfo.SignerType.KEY, infoKey.getSignerType());
    assertTrue(new Name("/my-key").equals(infoKey.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm());

    SigningInfo infoCert = new SigningInfo("cert:/my-cert");
    assertEquals(SigningInfo.SignerType.CERT, infoCert.getSignerType());
    assertTrue(new Name("/my-cert").equals(infoCert.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm());

    SigningInfo infoSha = new SigningInfo("id:/localhost/identity/digest-sha256");
    assertEquals(SigningInfo.SignerType.SHA256, infoSha.getSignerType());
    assertTrue(new Name().equals(infoSha.getSignerName()));
    assertEquals(DigestAlgorithm.SHA256, infoSha.getDigestAlgorithm());
  }

  @Test
  public void
  testToString()
  {
    assertEquals("", "" + new SigningInfo());

    assertEquals("id:/my-identity",
      "" + new SigningInfo(SigningInfo.SignerType.ID, new Name("/my-identity")));
    assertEquals("key:/my-key",
      "" + new SigningInfo(SigningInfo.SignerType.KEY, new Name("/my-key")));
    assertEquals("cert:/my-cert",
      "" + new SigningInfo(SigningInfo.SignerType.CERT, new Name("/my-cert")));
    assertEquals("id:/localhost/identity/digest-sha256",
      "" + new SigningInfo(SigningInfo.SignerType.SHA256));
  }

  @Test
  public void
  testChaining()
  {
    SigningInfo info = new SigningInfo()
      .setSigningIdentity(new Name("/identity"))
      .setSigningKeyName(new Name("/key/name"))
      .setSigningCertificateName(new Name("/cert/name"))
      .setPibIdentity(null)
      .setPibKey(null)
      .setSha256Signing()
      .setDigestAlgorithm(DigestAlgorithm.SHA256);

    assertEquals("id:/localhost/identity/digest-sha256", "" + info);
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
