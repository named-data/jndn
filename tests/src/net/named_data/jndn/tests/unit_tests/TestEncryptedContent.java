/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/encrypted-content.t.cpp
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

import java.nio.ByteBuffer;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestEncryptedContent {
  // Convert the int array to a ByteBuffer.
  private static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer ENCRYPTED = toBuffer(new int[] {
0x82, 0x30, // EncryptedContent
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, // 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, // 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
  0x83, 0x01, // EncryptedAlgorithm
    0x03,
  0x85, 0x0a, // InitialVector
    0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  });

  private static final ByteBuffer ENCRYPTED_NO_IV = toBuffer(new int[] {
0x82, 0x24, // EncryptedContent
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, // 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, // 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
  0x83, 0x01, // EncryptedAlgorithm
    0x03,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  });

  private static final ByteBuffer MESSAGE = toBuffer(new int[] {
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  });

  private static final ByteBuffer IV = toBuffer(new int[] {
    0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
  });

  @Test
  public void
  testConstructor() throws EncodingException
  {
    EncryptedContent content = new EncryptedContent();
    assertEquals(null, content.getAlgorithmType());
    assertEquals(true, content.getPayload().isNull());
    assertEquals(true, content.getInitialVector().isNull());
    assertEquals(KeyLocatorType.NONE, content.getKeyLocator().getType());

    Blob payload = new Blob(MESSAGE, false);
    Blob initialVector = new Blob(IV, false);

    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    content.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(payload)
      .setInitialVector(initialVector);

    // Test the copy constructor.
    EncryptedContent sha256RsaContent = new EncryptedContent(content);
    Blob contentPayload = sha256RsaContent.getPayload();
    Blob contentInitialVector = sha256RsaContent.getInitialVector();

    assertEquals(EncryptAlgorithmType.RsaOaep, sha256RsaContent.getAlgorithmType());
    assertTrue(contentPayload.equals(payload));
    assertTrue(contentInitialVector.equals(initialVector));
    assertTrue(sha256RsaContent.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    Blob encryptedBlob = new Blob(ENCRYPTED, false);
    Blob encoded = sha256RsaContent.wireEncode();

    assertTrue(encryptedBlob.equals(encoded));

    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.wireDecode(encryptedBlob);
    contentPayload = sha256RsaContent.getPayload();
    contentInitialVector = sha256RsaContent.getInitialVector();

    assertEquals(EncryptAlgorithmType.RsaOaep, sha256RsaContent.getAlgorithmType());
    assertTrue(contentPayload.equals(payload));
    assertTrue(contentInitialVector.equals(initialVector));
    assertTrue(sha256RsaContent.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    // Test no IV.
    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(payload);
    contentPayload = sha256RsaContent.getPayload();

    assertEquals(EncryptAlgorithmType.RsaOaep, sha256RsaContent.getAlgorithmType());
    assertTrue(contentPayload.equals(payload));
    assertTrue(sha256RsaContent.getInitialVector().isNull());
    assertTrue(sha256RsaContent.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    encryptedBlob = new Blob(ENCRYPTED_NO_IV, false);
    Blob encodedNoIv = sha256RsaContent.wireEncode();

    assertTrue(encryptedBlob.equals(encodedNoIv));

    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.wireDecode(encryptedBlob);
    Blob contentPayloadNoIV = sha256RsaContent.getPayload();

    assertEquals(EncryptAlgorithmType.RsaOaep, sha256RsaContent.getAlgorithmType());
    assertTrue(contentPayloadNoIV.equals(payload));
    assertTrue(sha256RsaContent.getInitialVector().isNull());
    assertTrue(sha256RsaContent.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));
}

  @Test
  public void
  testDecodingError()
  {
    EncryptedContent encryptedContent = new EncryptedContent();

    Blob errorBlob1 = new Blob(toBuffer(new int[] {
      0x1f, 0x30, // Wrong EncryptedContent (0x82, 0x24)
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob1);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }

    Blob errorBlob2 = new Blob(toBuffer(new int[] {
      0x82, 0x30, // EncryptedContent
        0x1d, 0x16, // Wrong KeyLocator (0x1c, 0x16)
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob2);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }

    Blob errorBlob3 = new Blob(toBuffer(new int[] {
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x1d, 0x01, // Wrong EncryptedAlgorithm (0x83, 0x01)
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob3);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }

    Blob errorBlob4 = new Blob(toBuffer(new int[] {
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74, // 'test'
            0x08, 0x03,
              0x6b, 0x65, 0x79, // 'key'
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x1f, 0x0a, // InitialVector (0x84, 0x0a)
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob4);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }

    Blob errorBlob5 = new Blob(toBuffer(new int[] {
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74, // 'test'
            0x08, 0x03,
              0x6b, 0x65, 0x79, // 'key'
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x21, 0x07, // EncryptedPayload (0x85, 0x07)
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob5);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }

    Blob errorBlob6 = new Blob(toBuffer(new int[] {
      0x82, 0x00 // Empty EncryptedContent
    }), false);
    try {
      encryptedContent.wireDecode(errorBlob6);
      fail("wireDecode did not throw an exception");
    }
    catch (EncodingException ex) {}
    catch (Exception ex) { fail("wireDecode did not throw EncodingException"); }
  }

  @Test
  public void
  testSetterGetter() throws EncodingException
  {
    EncryptedContent content = new EncryptedContent();
    assertEquals(null, content.getAlgorithmType());
    assertEquals(true, content.getPayload().isNull());
    assertEquals(true, content.getInitialVector().isNull());
    assertEquals(KeyLocatorType.NONE, content.getKeyLocator().getType());

    content.setAlgorithmType(EncryptAlgorithmType.RsaOaep);
    assertEquals(EncryptAlgorithmType.RsaOaep, content.getAlgorithmType());
    assertEquals(true, content.getPayload().isNull());
    assertEquals(true, content.getInitialVector().isNull());
    assertEquals(KeyLocatorType.NONE, content.getKeyLocator().getType());

    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    content.setKeyLocator(keyLocator);
    assertTrue(content.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(content.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));
    assertEquals(true, content.getPayload().isNull());
    assertEquals(true, content.getInitialVector().isNull());

    Blob payload = new Blob(MESSAGE, false);
    content.setPayload(payload);

    Blob contentPayload = content.getPayload();
    assertTrue(contentPayload.equals(payload));

    Blob initialVector = new Blob(IV, false);
    content.setInitialVector(initialVector);

    Blob contentInitialVector = content.getInitialVector();
    assertTrue(contentInitialVector.equals(initialVector));

    Blob encoded = content.wireEncode();
    Blob contentBlob = new Blob(ENCRYPTED, false);

    assertTrue(contentBlob.equals(encoded));
  }
}