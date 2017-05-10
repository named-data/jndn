/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager.t.cpp
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
import java.text.ParseException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.encrypt.Sqlite3GroupManagerDb;
import net.named_data.jndn.encrypt.GroupManager;
import net.named_data.jndn.encrypt.GroupManagerDb;
import net.named_data.jndn.encrypt.Interval;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import net.named_data.jndn.encrypt.Schedule;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.security.policy.NoVerifyPolicyManager;
import net.named_data.jndn.util.Blob;
import static net.named_data.jndn.encrypt.Schedule.toIsoString;
import static net.named_data.jndn.encrypt.Schedule.fromIsoString;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestGroupManager implements GroupManager.Friend {
  // Convert the int array to a ByteBuffer.
  public static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer SIG_INFO = toBuffer(new int[] {
  0x16, 0x1b, // SignatureInfo
      0x1b, 0x01, // SignatureType
          0x01,
      0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
              0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
              0x08, 0x03,
                  0x6b, 0x65, 0x79,
              0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
  });

  private static final ByteBuffer SIG_VALUE = toBuffer(new int[] {
  0x17, 0x80, // SignatureValue
      0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
      0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
      0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
      0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
      0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
      0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
      0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
      0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
      0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
      0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
  });

  @Before
  public void
  setUp() throws EncodingException, DerEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, UnrecognizedKeyFormatException, DerDecodingException, SecurityException
  {
    // Don't show INFO log messages.
    Logger.getLogger("").setLevel(Level.WARNING);

    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();

    dKeyDatabaseFilePath = new File(policyConfigDirectory, "manager-d-key-test.db");
    dKeyDatabaseFilePath.delete();

    eKeyDatabaseFilePath = new File(policyConfigDirectory, "manager-e-key-test.db");
    eKeyDatabaseFilePath.delete();

    intervalDatabaseFilePath = new File(policyConfigDirectory, "manager-interval-test.db");
    intervalDatabaseFilePath.delete();

    groupKeyDatabaseFilePath = new File(policyConfigDirectory, "manager-group-key-test.db");
    groupKeyDatabaseFilePath.delete();

    RsaKeyParams params = new RsaKeyParams();
    DecryptKey memberDecryptKey = RsaAlgorithm.generateKey(params);
    decryptKeyBlob = memberDecryptKey.getKeyBits();
    EncryptKey memberEncryptKey = RsaAlgorithm.deriveEncryptKey(decryptKeyBlob);
    encryptKeyBlob = memberEncryptKey.getKeyBits();

    // Generate the certificate.
    certificate.setName(new Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    PublicKey contentPublicKey = new PublicKey(encryptKeyBlob);
    certificate.setPublicKeyInfo(contentPublicKey);
    certificate.setNotBefore(0);
    certificate.setNotAfter(0);
    certificate.encode();

    Blob signatureInfoBlob = new Blob(SIG_INFO, false);
    Blob signatureValueBlob = new Blob(SIG_VALUE, false);

    Signature signature = TlvWireFormat.get().decodeSignatureInfoAndValue
      (signatureInfoBlob.buf(), signatureValueBlob.buf());
    certificate.setSignature(signature);

    certificate.wireEncode();

    // Set up the keyChain.
    MemoryIdentityStorage identityStorage = new MemoryIdentityStorage();
    MemoryPrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();
    keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new NoVerifyPolicyManager());
    Name identityName = new Name("TestGroupManager");
    keyChain.createIdentityAndCertificate(identityName);
    keyChain.getIdentityManager().setDefaultIdentity(identityName);

    GroupManager.setFriendAccess(this);
  }

  public void
  setGroupManagerFriendAccess(GroupManager.FriendAccess friendAccess)
  {
    this.friendAccess = friendAccess;
  }

  void
  setManager(GroupManager manager)
    throws EncodingException, GroupManagerDb.Error, DerDecodingException,
      ParseException
  {
    // Set up the first schedule.
    Schedule schedule1 = new Schedule();
    RepetitiveInterval interval11 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150827T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval12 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150827T000000"), 6, 8, 1,
       RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval13 = new RepetitiveInterval
      (fromIsoString("20150827T000000"),
       fromIsoString("20150827T000000"), 7, 8);
    schedule1.addWhiteInterval(interval11);
    schedule1.addWhiteInterval(interval12);
    schedule1.addBlackInterval(interval13);

    // Set up the second schedule.
    Schedule schedule2 = new Schedule();
    RepetitiveInterval interval21 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150827T000000"), 9, 12, 1, 
       RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval22 = new RepetitiveInterval
      (fromIsoString("20150827T000000"),
       fromIsoString("20150827T000000"), 6, 8);
    RepetitiveInterval interval23 = new RepetitiveInterval
      (fromIsoString("20150827T000000"),
       fromIsoString("20150827T000000"), 2, 4);
    schedule2.addWhiteInterval(interval21);
    schedule2.addWhiteInterval(interval22);
    schedule2.addBlackInterval(interval23);

    // Add them to the group manager database.
    manager.addSchedule("schedule1", schedule1);
    manager.addSchedule("schedule2", schedule2);

    // Make some adaptions to certificate.
    Blob dataBlob = certificate.wireEncode();

    Data memberA = new Data();
    memberA.wireDecode(dataBlob, TlvWireFormat.get());
    memberA.setName(new Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    Data memberB = new Data();
    memberB.wireDecode(dataBlob, TlvWireFormat.get());
    memberB.setName(new Name("/ndn/memberB/KEY/ksk-123/ID-CERT/123"));
    Data memberC = new Data();
    memberC.wireDecode(dataBlob, TlvWireFormat.get());
    memberC.setName(new Name("/ndn/memberC/KEY/ksk-123/ID-CERT/123"));

    // Add the members to the database.
    manager.addMember("schedule1", memberA);
    manager.addMember("schedule1", memberB);
    manager.addMember("schedule2", memberC);
  }

  @After
  public void
  tearDown()
  {
    dKeyDatabaseFilePath.delete();
    eKeyDatabaseFilePath.delete();
    intervalDatabaseFilePath.delete();
    groupKeyDatabaseFilePath.delete();
  }

  @Test
  public void
  testCreateDKeyData()
    throws SecurityException, GroupManagerDb.Error, EncodingException,
      InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    // Create the group manager.
    GroupManager manager = new GroupManager
      (new Name("Alice"), new Name("data_type"), 
       new Sqlite3GroupManagerDb(dKeyDatabaseFilePath.getAbsolutePath()), 2048, 1,
       keyChain);

    Blob newCertificateBlob = certificate.wireEncode();
    IdentityCertificate newCertificate = new IdentityCertificate();
    newCertificate.wireDecode(newCertificateBlob);

    // Encrypt the D-KEY.
    Data data = friendAccess.createDKeyData
      (manager, "20150825T000000", "20150827T000000", new Name("/ndn/memberA/KEY"),
       decryptKeyBlob, newCertificate.getPublicKeyInfo().getKeyDer());

    // Verify the encrypted D-KEY.
    Blob dataContent = data.getContent();

    // Get the nonce key.
    // dataContent is a sequence of the two EncryptedContent.
    EncryptedContent encryptedNonce = new EncryptedContent();
    encryptedNonce.wireDecode(dataContent);
    assertEquals(0, encryptedNonce.getInitialVector().size());
    assertEquals(EncryptAlgorithmType.RsaOaep, encryptedNonce.getAlgorithmType());

    Blob blobNonce = encryptedNonce.getPayload();
    EncryptParams decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    Blob nonce = RsaAlgorithm.decrypt(decryptKeyBlob, blobNonce, decryptParams);

    // Get the D-KEY.
    // Use the size of encryptedNonce to find the start of encryptedPayload.
    ByteBuffer payloadContent = dataContent.buf().duplicate();
    payloadContent.position(encryptedNonce.wireEncode().size());
    EncryptedContent encryptedPayload = new EncryptedContent();
    encryptedPayload.wireDecode(payloadContent);
    assertEquals(16, encryptedPayload.getInitialVector().size());
    assertEquals(EncryptAlgorithmType.AesCbc, encryptedPayload.getAlgorithmType());

    decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
    decryptParams.setInitialVector(encryptedPayload.getInitialVector());
    Blob blobPayload = encryptedPayload.getPayload();
    Blob largePayload = AesAlgorithm.decrypt(nonce, blobPayload, decryptParams);

    assertTrue(largePayload.equals(decryptKeyBlob));
  }

  @Test
  public void
  testCreateEKeyData() 
    throws SecurityException, GroupManagerDb.Error, EncodingException,
      DerDecodingException, ParseException
  {
    // Create the group manager.
    GroupManager manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(eKeyDatabaseFilePath.getAbsolutePath()), 1024, 1,
       keyChain);
    setManager(manager);

    Data data = friendAccess.createEKeyData
      (manager, "20150825T090000", "20150825T110000", encryptKeyBlob);
    assertEquals("/Alice/READ/data_type/E-KEY/20150825T090000/20150825T110000",
                 data.getName().toUri());

    Blob contentBlob = data.getContent();
    assertTrue(encryptKeyBlob.equals(contentBlob));
  }

  @Test
  public void
  testCalculateInterval()
    throws SecurityException, GroupManagerDb.Error, EncodingException,
      DerDecodingException, ParseException
  {
    // Create the group manager.
    GroupManager manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(intervalDatabaseFilePath.getAbsolutePath()), 1024, 1,
       keyChain);
    setManager(manager);

    Map memberKeys = new HashMap();
    Interval result;

    double timePoint1 = fromIsoString("20150825T093000");
    result = friendAccess.calculateInterval(manager, timePoint1, memberKeys);
    assertEquals("20150825T090000", toIsoString(result.getStartTime()));
    assertEquals("20150825T100000", toIsoString(result.getEndTime()));

    double timePoint2 = fromIsoString("20150827T073000");
    result = friendAccess.calculateInterval(manager, timePoint2, memberKeys);
    assertEquals("20150827T070000", toIsoString(result.getStartTime()));
    assertEquals("20150827T080000", toIsoString(result.getEndTime()));

    double timePoint3 = fromIsoString("20150827T043000");
    result = friendAccess.calculateInterval(manager, timePoint3, memberKeys);
    assertEquals(false, result.isValid());

    double timePoint4 = fromIsoString("20150827T053000");
    result = friendAccess.calculateInterval(manager, timePoint4, memberKeys);
    assertEquals("20150827T050000", toIsoString(result.getStartTime()));
    assertEquals("20150827T060000", toIsoString(result.getEndTime()));
  }

  @Test
  public void
  testGetGroupKey()
    throws SecurityException, GroupManagerDb.Error, EncodingException,
      DerDecodingException, ParseException, InvalidKeySpecException,
      NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException
  {
    // Create the group manager.
    GroupManager manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(groupKeyDatabaseFilePath.getAbsolutePath()), 1024, 1,
       keyChain);
    setManager(manager);

    // Get the data list from the group manager.
    double timePoint1 = fromIsoString("20150825T093000");
    List result = manager.getGroupKey(timePoint1);

    assertEquals(4, result.size());

    // The first data packet contains the group's encryption key (public key).
    Data data = (Data)result.get(0);
    assertEquals
      ("/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
       data.getName().toUri());
    EncryptKey groupEKey = new EncryptKey(data.getContent());

    // Get the second data packet and decrypt.
    data = (Data)result.get(1);
    assertEquals
      ("/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
       data.getName().toUri());

    /////////////////////////////////////////////////////// Start decryption.
    Blob dataContent = data.getContent();

    // Get the nonce key.
    // dataContent is a sequence of the two EncryptedContent.
    EncryptedContent encryptedNonce = new EncryptedContent();
    encryptedNonce.wireDecode(dataContent);
    assertEquals(0, encryptedNonce.getInitialVector().size());
    assertEquals(EncryptAlgorithmType.RsaOaep, encryptedNonce.getAlgorithmType());

    EncryptParams decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    Blob blobNonce = encryptedNonce.getPayload();
    Blob nonce = RsaAlgorithm.decrypt(decryptKeyBlob, blobNonce, decryptParams);

    // Get the payload.
    // Use the size of encryptedNonce to find the start of encryptedPayload.
    ByteBuffer payloadContent = dataContent.buf().duplicate();
    payloadContent.position(encryptedNonce.wireEncode().size());
    EncryptedContent encryptedPayload = new EncryptedContent();
    encryptedPayload.wireDecode(payloadContent);
    assertEquals(16, encryptedPayload.getInitialVector().size());
    assertEquals(EncryptAlgorithmType.AesCbc, encryptedPayload.getAlgorithmType());

    decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
    decryptParams.setInitialVector(encryptedPayload.getInitialVector());
    Blob blobPayload = encryptedPayload.getPayload();
    Blob largePayload = AesAlgorithm.decrypt(nonce, blobPayload, decryptParams);

    // Get the group D-KEY.
    DecryptKey groupDKey = new DecryptKey(largePayload);

    /////////////////////////////////////////////////////// End decryption.

    // Check the D-KEY.
    EncryptKey derivedGroupEKey = RsaAlgorithm.deriveEncryptKey
      (groupDKey.getKeyBits());
    assertTrue(groupEKey.getKeyBits().equals(derivedGroupEKey.getKeyBits()));

    // Check the third data packet.
    data = (Data)result.get(2);
    assertEquals
      ("/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberB/ksk-123",
       data.getName().toUri());

    // Check the fourth data packet.
    data = (Data)result.get(3);
    assertEquals
      ("/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberC/ksk-123",
       data.getName().toUri());

    // Check invalid time stamps for getting the group key.
    double timePoint2 = fromIsoString("20150826T083000");
    assertEquals(0, manager.getGroupKey(timePoint2).size());

    double timePoint3 = fromIsoString("20150827T023000");
    assertEquals(0, manager.getGroupKey(timePoint3).size());
  }

  @Test
  public void
  testGetGroupKeyWithoutRegeneration()
    throws SecurityException, GroupManagerDb.Error, EncodingException,
      DerDecodingException, ParseException
  {
    // Create the group manager.
    GroupManager manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(groupKeyDatabaseFilePath.getAbsolutePath()), 1024, 1,
       keyChain);
    setManager(manager);

    // Get the data list from the group manager.
    double timePoint1 = fromIsoString("20150825T093000");
    List result = manager.getGroupKey(timePoint1);

    assertEquals(4, result.size());

    // The first data packet contains the group's encryption key (public key).
    Data data1 = (Data)result.get(0);
    assertEquals
      ("/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
       data1.getName().toUri());
    EncryptKey groupEKey1 = new EncryptKey(data1.getContent());

    // Get the second data packet.
    data1 = (Data)result.get(1);
    assertEquals
      ("/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
       data1.getName().toUri());

    // Add new members to the database.
    Blob dataBlob = certificate.wireEncode();
    Data memberD = new Data();
    memberD.wireDecode(dataBlob);
    memberD.setName(new Name("/ndn/memberD/KEY/ksk-123/ID-CERT/123"));
    manager.addMember("schedule1", memberD);

    List result2 = manager.getGroupKey(timePoint1, false);
    assertEquals(5, result2.size());

    // Check that the new EKey is the same as the previous one.
    Data data2 = (Data)result2.get(0);
    assertEquals
      ("/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
       data2.getName().toUri());
    EncryptKey groupEKey2 = new EncryptKey(data2.getContent());
    assertTrue(groupEKey1.getKeyBits().equals(groupEKey2.getKeyBits()));

    // Check the second data packet.
    data2 = (Data)result2.get(1);
    assertEquals
      ("/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
       data2.getName().toUri());
  }

  private File dKeyDatabaseFilePath;
  private File eKeyDatabaseFilePath;
  private File intervalDatabaseFilePath;
  private File groupKeyDatabaseFilePath;
  private Blob decryptKeyBlob;
  private Blob encryptKeyBlob;
  private final IdentityCertificate certificate = new IdentityCertificate();
  private KeyChain keyChain;
  private GroupManager.FriendAccess friendAccess;
}
