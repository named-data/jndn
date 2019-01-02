/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/name-based-access-control/blob/new/tests/tests/access-manager.t.cpp
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.AccessManagerV2;
import net.named_data.jndn.encrypt.EncryptorV2;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TestAccessManagerV2 {
  static class AccessManagerFixture extends IdentityManagementFixture {
    public AccessManagerFixture()
      throws Pib.Error, PibImpl.Error, UnrecognizedKeyFormatException,
        EncodingException, TpmBackEnd.Error, KeyChain.Error,
        InvalidKeySpecException, NoSuchAlgorithmException,
        NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
        BadPaddingException, CertificateV2.Error, SecurityException, Tpm.Error,
        IOException
    {
      face_ = new InMemoryStorageFace(new InMemoryStorageRetaining());
      accessIdentity_ = addIdentity(new Name("/access/policy/identity"));
      // This is a hack to get access to the KEK key-id.
      nacIdentity_ = addIdentity
        (new Name("/access/policy/identity/NAC/dataset"), new RsaKeyParams());
      userIdentities_.add(addIdentity(new Name("/first/user"), new RsaKeyParams()));
      userIdentities_.add(addIdentity(new Name("/second/user"), new RsaKeyParams()));
      manager_ = new AccessManagerV2
        (accessIdentity_, new Name("/dataset"), keyChain_, face_);

      for (PibIdentity user : userIdentities_)
        manager_.addMember(user.getDefaultKey().getDefaultCertificate());
    }

    public final InMemoryStorageFace face_;
    public final PibIdentity accessIdentity_;
    public final PibIdentity nacIdentity_;
    public final ArrayList<PibIdentity> userIdentities_ =
      new ArrayList<PibIdentity>();
    public final AccessManagerV2 manager_;
  }

  AccessManagerFixture fixture_;

  @Before
  public void
  setUp()
    throws Pib.Error, PibImpl.Error, UnrecognizedKeyFormatException,
      EncodingException, TpmBackEnd.Error, KeyChain.Error,
      InvalidKeySpecException, NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, CertificateV2.Error, SecurityException, Tpm.Error,
      IOException
  {
    // Turn off INFO log messages.
    Logger.getLogger("").setLevel(Level.SEVERE);

    fixture_ = new AccessManagerFixture();
  }

  @Test
  public void
  testPublishedKek() throws Pib.Error, PibImpl.Error
  {
    fixture_.face_.receive(new Interest
      (new Name("/access/policy/identity/NAC/dataset/KEK"))
       .setCanBePrefix(true).setMustBeFresh(true));

    assertTrue(fixture_.face_.sentData_.get(0).getName().getPrefix(-1).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assertTrue(fixture_.face_.sentData_.get(0).getName().get(-1).equals
      (fixture_.nacIdentity_.getDefaultKey().getName().get(-1)));
  }

  @Test
  public void
  testPublishedKdks() throws Pib.Error, PibImpl.Error
  {
    for (PibIdentity user : fixture_.userIdentities_) {
      Name kdkName = new Name("/access/policy/identity/NAC/dataset/KDK");
      kdkName
        .append(fixture_.nacIdentity_.getDefaultKey().getName().get(-1))
        .append("ENCRYPTED-BY")
        .append(user.getDefaultKey().getName());

      fixture_.face_.receive
        (new Interest(kdkName).setCanBePrefix(true).setMustBeFresh(true));

      assertTrue("Sent Data does not have the KDK name " + kdkName.toUri(),
        fixture_.face_.sentData_.get(0).getName().equals(kdkName));
      fixture_.face_.sentData_.clear();
    }
  }

  @Test
  public void
  testEnumerateDataFromInMemoryStorage()
  {
    assertEquals(3, fixture_.manager_.size());

    int nKek = 0;
    int nKdk = 0;
    for (Object data : fixture_.manager_.getCache_().values()) {
      if (((Data)data).getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KEK))
        ++nKek;
      if (((Data)data).getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KDK))
        ++nKdk;
    }

    assertEquals(1, nKek);
    assertEquals(2, nKdk);
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
