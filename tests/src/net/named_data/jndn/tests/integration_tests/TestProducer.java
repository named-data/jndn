/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer.t.cpp
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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Link;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.encrypt.Producer;
import net.named_data.jndn.encrypt.ProducerDb;
import net.named_data.jndn.encrypt.Sqlite3ProducerDb;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.Encryptor;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.security.policy.NoVerifyPolicyManager;
import net.named_data.jndn.util.Blob;
import static net.named_data.jndn.encrypt.Schedule.fromIsoString;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestProducer {
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

  private static final ByteBuffer DATA_CONTENT = toBuffer(new int[] {
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
  });

  @Before
  public void
  setUp()
    throws ConsumerDb.Error, NoSuchAlgorithmException,
      InvalidKeySpecException, DerDecodingException, SecurityException
  {
    // Don't show INFO log messages.
    Logger.getLogger("").setLevel(Level.WARNING);

    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();
    databaseFilePath = new File(policyConfigDirectory, "test.db");
    databaseFilePath.delete();

    // Set up the key chain.
    MemoryIdentityStorage identityStorage = new MemoryIdentityStorage();
    MemoryPrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();
    keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new NoVerifyPolicyManager());
    Name identityName = new Name("TestProducer");
    certificateName = keyChain.createIdentityAndCertificate(identityName);
    keyChain.getIdentityManager().setDefaultIdentity(identityName);
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  void
  createEncryptionKey(Name eKeyName, Name timeMarker)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException, SecurityException, DerDecodingException
  {
    RsaKeyParams params = new RsaKeyParams();
    eKeyName = new Name(eKeyName);
    eKeyName.append(timeMarker);

    Blob dKeyBlob = RsaAlgorithm.generateKey(params).getKeyBits();
    Blob eKeyBlob = RsaAlgorithm.deriveEncryptKey(dKeyBlob).getKeyBits();
    decryptionKeys.put(eKeyName, dKeyBlob);

    Data keyData = new Data(eKeyName);
    keyData.setContent(eKeyBlob);
    keyChain.sign(keyData, certificateName);
    encryptionKeys.put(eKeyName, keyData);
  }

  @Test
  public void
  testContentKeyRequest() 
    throws EncodingException, ParseException, NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException,
      InvalidKeySpecException, SecurityException, DerDecodingException, 
      ProducerDb.Error, IOException
  {
    Name prefix = new Name("/prefix");
    Name suffix = new Name("/a/b/c");
    Name expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    Name cKeyName = new Name(prefix);
    cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE);
    cKeyName.append(suffix);
    cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);

    Name timeMarker = new Name("20150101T100000/20150101T120000");
    final double testTime1 = fromIsoString("20150101T100001");
    final double testTime2 = fromIsoString("20150101T110001");
    final Name.Component testTimeRounded1 = new Name.Component("20150101T100000");
    final Name.Component testTimeRounded2 = new Name.Component("20150101T110000");
    Name.Component testTimeComponent2 = new Name.Component("20150101T110001");

    // Create content keys required for this test case:
    for (int i = 0; i < suffix.size(); ++i) {
      createEncryptionKey(expectedInterest, timeMarker);
      expectedInterest = expectedInterest.getPrefix(-2).append
        (Encryptor.NAME_COMPONENT_E_KEY);
    }

    int[] expressInterestCallCount = new int[] { 0 };

    // Prepare a LocalTestFace to instantly answer calls to expressInterest.
    class LocalTestFace extends Face {
      public LocalTestFace(Name timeMarker, int[] expressInterestCallCount)
      {
        super("localhost");

        timeMarker_ = timeMarker;
        expressInterestCallCount_ = expressInterestCallCount;
      }

      public long
      expressInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
      {
        ++expressInterestCallCount_[0];
        
        Name interestName = new Name(interest.getName());
        interestName.append(timeMarker_);
        assertEquals(true, encryptionKeys.containsKey(interestName));
        onData.onData(interest, (Data)encryptionKeys.get(interestName));

        return 0;
      }

      private final Name timeMarker_;
      private int[] expressInterestCallCount_;
    }

    LocalTestFace face = new LocalTestFace(timeMarker, expressInterestCallCount);

    // Verify that the content key is correctly encrypted for each domain, and
    // the produce method encrypts the provided data with the same content key.
    ProducerDb testDb = new Sqlite3ProducerDb(databaseFilePath.getAbsolutePath());
    Producer producer = new Producer(prefix, suffix, face, keyChain, testDb);
    Blob[] contentKey = new Blob[] { null };

    class CheckEncryptionKeys {
      public CheckEncryptionKeys
        (int[] expressInterestCallCount, Blob[] contentKey, Name cKeyName,
         ProducerDb testDb)
      {
        expressInterestCallCount_ = expressInterestCallCount;
        contentKey_ = contentKey;
        cKeyName_ = cKeyName;
        testDb_ = testDb;
      }

      public void
      checkEncryptionKeys
        (List result, double testTime, Name.Component roundedTime,
         int expectedExpressInterestCallCount)
      {
        assertEquals(expectedExpressInterestCallCount, expressInterestCallCount_[0]);

        try {
          assertEquals(true, testDb_.hasContentKey(testTime));
          contentKey_[0] = testDb_.getContentKey(testTime);
        } catch (ProducerDb.Error ex) { fail("Error in ProducerDb: " + ex); }

        EncryptParams params = new EncryptParams(EncryptAlgorithmType.RsaOaep);
        for (int i = 0; i < result.size(); ++i) {
          Data key = (Data)result.get(i);
          Name keyName = key.getName();
          assertEquals(cKeyName_, keyName.getSubName(0, 6));
          assertEquals(keyName.get(6), roundedTime);
          assertEquals(keyName.get(7), Encryptor.NAME_COMPONENT_FOR);
          assertEquals(true, decryptionKeys.containsKey(keyName.getSubName(8)));

          Blob decryptionKey = (Blob)decryptionKeys.get(keyName.getSubName(8));
          assertEquals(true, decryptionKey.size() != 0);
          Blob encryptedKeyEncoding = key.getContent();

          EncryptedContent content = new EncryptedContent();
          try {
            content.wireDecode(encryptedKeyEncoding);
          } catch (EncodingException ex) {
            fail("Error decoding EncryptedContent" + ex);
          }
          Blob encryptedKey = content.getPayload();
          Blob retrievedKey = null;
          try {
            retrievedKey = RsaAlgorithm.decrypt
              (decryptionKey, encryptedKey, params);
          } catch (Exception ex) {
            fail("Error in RsaAlgorithm.decrypt: " + ex);
          }

          assertTrue(contentKey_[0].equals(retrievedKey));
        }

        assertEquals(3, result.size());
      }

      private final int[] expressInterestCallCount_;
      private final Blob[] contentKey_;
      private final Name cKeyName_;
      private final ProducerDb testDb_;
    }

    final CheckEncryptionKeys checkEncryptionKeys = new CheckEncryptionKeys
      (expressInterestCallCount, contentKey, cKeyName, testDb);

    // An initial test to confirm that keys are created for this time slot.
    Name contentKeyName1 = producer.createContentKey
      (testTime1,
       new Producer.OnEncryptedKeys() {
         public void onEncryptedKeys(List keys) {
           checkEncryptionKeys.checkEncryptionKeys
             (keys, testTime1, testTimeRounded1, 3);
         }
       });

    // Verify that we do not repeat the search for e-keys. The total
    //   expressInterestCallCount should be the same.
    Name contentKeyName2 = producer.createContentKey
      (testTime2,
       new Producer.OnEncryptedKeys() {
         public void onEncryptedKeys(List keys) {
           checkEncryptionKeys.checkEncryptionKeys
             (keys, testTime2, testTimeRounded2, 3);
         }
       });

    // Confirm content key names are correct
    assertEquals(cKeyName, contentKeyName1.getPrefix(-1));
    assertEquals(testTimeRounded1, contentKeyName1.get(6));
    assertEquals(cKeyName, contentKeyName2.getPrefix(-1));
    assertEquals(testTimeRounded2, contentKeyName2.get(6));

    // Confirm that produce encrypts with the correct key and has the right name.
    Data testData = new Data();
    producer.produce(testData, testTime2, new Blob(DATA_CONTENT, false));

    Name producedName = testData.getName();
    assertEquals(cKeyName.getPrefix(-1), producedName.getSubName(0, 5));
    assertEquals(testTimeComponent2, producedName.get(5));
    assertEquals(Encryptor.NAME_COMPONENT_FOR, producedName.get(6));
    assertEquals(cKeyName, producedName.getSubName(7, 6));
    assertEquals(testTimeRounded2, producedName.get(13));

    Blob dataBlob = testData.getContent();

    EncryptedContent dataContent = new EncryptedContent();
    dataContent.wireDecode(dataBlob);
    Blob encryptedData = dataContent.getPayload();
    Blob initialVector = dataContent.getInitialVector();

    EncryptParams params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
    params.setInitialVector(initialVector);
    Blob decryptTest = AesAlgorithm.decrypt(contentKey[0], encryptedData, params);
    assertTrue(decryptTest.equals(new Blob(DATA_CONTENT, false)));
  }

  @Test
  public void
  testContentKeySearch()
    throws ParseException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      SecurityException, DerDecodingException, ProducerDb.Error, IOException, EncodingException
  {
    Name timeMarkerFirstHop = new Name("20150101T070000/20150101T080000");
    Name timeMarkerSecondHop = new Name("20150101T080000/20150101T090000");
    final Name timeMarkerThirdHop = new Name("20150101T100000/20150101T110000");

    Name prefix = new Name("/prefix");
    Name suffix = new Name("/suffix");
    final Name expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    final Name cKeyName = new Name(prefix);
    cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE);
    cKeyName.append(suffix);
    cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);

    double testTime = fromIsoString("20150101T100001");

    // Create content keys required for this test case:
    createEncryptionKey(expectedInterest, timeMarkerFirstHop);
    createEncryptionKey(expectedInterest, timeMarkerSecondHop);
    createEncryptionKey(expectedInterest, timeMarkerThirdHop);

    final int[] requestCount = new int[] { 0 };

    // Prepare a LocalTestFace to instantly answer calls to expressInterest.
    class LocalTestFace2 extends Face {
      public LocalTestFace2
        (Name expectedInterest, Name timeMarkerFirstHop,
         Name timeMarkerSecondHop, Name timeMarkerThirdHop,
         int[] requestCount)
      {
        super("localhost");

        expectedInterest_ = expectedInterest;
        timeMarkerFirstHop_ = timeMarkerFirstHop;
        timeMarkerSecondHop_ = timeMarkerSecondHop;
        timeMarkerThirdHop_ = timeMarkerThirdHop;
        requestCount_ = requestCount;
      }

      public long
      expressInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
      {
        assertEquals(expectedInterest_, interest.getName());

        boolean gotInterestName = false;
        Name interestName = null;
        for (int i = 0; i < 3; ++i) {
          interestName = new Name(interest.getName());
          if (i == 0)
            interestName.append(timeMarkerFirstHop_);
          else if (i == 1)
            interestName.append(timeMarkerSecondHop_);
          else if (i == 2)
            interestName.append(timeMarkerThirdHop_);

          // matchesName will check the Exclude.
          if (interest.matchesName(interestName)) {
            gotInterestName = true;
            ++requestCount_[0];
            break;
          }
        }

        if (gotInterestName)
          onData.onData(interest, (Data)encryptionKeys.get(interestName));

        return 0;
      }

      private final Name expectedInterest_;
      private final Name timeMarkerFirstHop_;
      private final Name timeMarkerSecondHop_;
      private final Name timeMarkerThirdHop_;
      private final int[] requestCount_;
    }

    LocalTestFace2 face = new LocalTestFace2
      (expectedInterest, timeMarkerFirstHop, timeMarkerSecondHop,
       timeMarkerThirdHop, requestCount);

    // Verify that if a key is found, but not within the right time slot, the
    // search is refined until a valid time slot is found.
    ProducerDb testDb = new Sqlite3ProducerDb(databaseFilePath.getAbsolutePath());
    Producer producer = new Producer(prefix, suffix, face, keyChain, testDb);
    producer.createContentKey
      (testTime,
       new Producer.OnEncryptedKeys() {
         public void onEncryptedKeys(List result) {
           assertEquals(3, requestCount[0]);
           assertEquals(1, result.size());

           Data keyData = (Data)result.get(0);
           Name keyName = keyData.getName();
           assertEquals(cKeyName, keyName.getSubName(0, 4));
           assertEquals(timeMarkerThirdHop.get(0), keyName.get(4));
           assertEquals(Encryptor.NAME_COMPONENT_FOR, keyName.get(5));
           assertEquals(expectedInterest.append(timeMarkerThirdHop),
                        keyName.getSubName(6));
         }
       });
  }

  @Test
  public void
  testContentKeyTimeout()
    throws ParseException, ProducerDb.Error, IOException, SecurityException, EncodingException
  {
    Name prefix = new Name("/prefix");
    Name suffix = new Name("/suffix");
    Name expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    double testTime = fromIsoString("20150101T100001");

    final int[] timeoutCount = new int[] { 0 };

    // Prepare a LocalTestFace to instantly answer calls to expressInterest.
    class LocalTestFace3 extends Face {
      public LocalTestFace3(Name expectedInterest, int[] timeoutCount)
      {
        super("localhost");

        expectedInterest_ = expectedInterest;
        timeoutCount_ = timeoutCount;
      }

      public long
      expressInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
      {
        assertEquals(expectedInterest_, interest.getName());
        ++timeoutCount_[0];
        onTimeout.onTimeout(interest);

        return 0;
      }

      private final Name expectedInterest_;
      private final int[] timeoutCount_;
    }

    LocalTestFace3 face = new LocalTestFace3(expectedInterest, timeoutCount);

    // Verify that if no response is received, the producer appropriately times
    // out. The result vector should not contain elements that have timed out.
    ProducerDb testDb = new Sqlite3ProducerDb(databaseFilePath.getAbsolutePath());
    Producer producer = new Producer(prefix, suffix, face, keyChain, testDb);
    producer.createContentKey
      (testTime,
       new Producer.OnEncryptedKeys() {
         public void onEncryptedKeys(List result) {
           assertEquals(4, timeoutCount[0]);
           assertEquals(0, result.size());
         }
       });
  }

  @Test
  public void
  testProducerWithLink()
    throws ParseException, ProducerDb.Error, IOException, SecurityException, EncodingException
  {
    Name prefix = new Name("/prefix");
    Name suffix = new Name("/suffix");
    Name expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    double testTime = fromIsoString("20150101T100001");

    final int[] timeoutCount = new int[] { 0 };

    // Prepare a LocalTestFace to instantly answer calls to expressInterest.
    class LocalTestFace4 extends Face {
      public LocalTestFace4(Name expectedInterest, int[] timeoutCount)
      {
        super("localhost");

        expectedInterest_ = expectedInterest;
        timeoutCount_ = timeoutCount;
      }

      public long
      expressInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack, WireFormat wireFormat) 
           throws IOException
      {
        assertEquals(expectedInterest_, interest.getName());
        try {
          assertEquals(3, interest.getLink().getDelegations().size());
        } catch (EncodingException ex) {
          fail("Error in getLink: " + ex);
        }
        ++timeoutCount_[0];
        onTimeout.onTimeout(interest);

        return 0;
      }

      private final Name expectedInterest_;
      private int[] timeoutCount_;
    }

    LocalTestFace4 face = new LocalTestFace4(expectedInterest, timeoutCount);

    // Verify that if no response is received, the producer appropriately times
    // out. The result vector should not contain elements that have timed out.
    Link link = new Link();
    link.addDelegation(10,  new Name("/test1"));
    link.addDelegation(20,  new Name("/test2"));
    link.addDelegation(100, new Name("/test3"));
    keyChain.sign(link);
    ProducerDb testDb = new Sqlite3ProducerDb(databaseFilePath.getAbsolutePath());
    Producer producer = new Producer
      (prefix, suffix, face, keyChain, testDb, 3, link);
    producer.createContentKey
      (testTime,
       new Producer.OnEncryptedKeys() {
         public void onEncryptedKeys(List result) {
           assertEquals(4, timeoutCount[0]);
           assertEquals(0, result.size());
         }
       });
  }

  File databaseFilePath;

  KeyChain keyChain;
  Name certificateName;

  Map decryptionKeys = new HashMap(); // key: Name, value: Blob
  Map encryptionKeys = new HashMap(); // key: Name, value: Data
}
