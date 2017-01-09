/**
 * Copyright (C) 2015-2017 Regents of the University of California.
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

  private static final ByteBuffer encrypted = toBuffer(new int[] {
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

  private static final ByteBuffer encryptedNoIv = toBuffer(new int[] {
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

  private static final ByteBuffer message = toBuffer(new int[] {
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  });

  private static final ByteBuffer iv = toBuffer(new int[] {
    0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
  });

  @Test
  public void
  testConstructor() throws EncodingException
  {
    // Check default settings.
    EncryptedContent content = new EncryptedContent();
    assertEquals(EncryptAlgorithmType.NONE, content.getAlgorithmType());
    assertEquals(true, content.getPayload().isNull());
    assertEquals(true, content.getInitialVector().isNull());
    assertEquals(KeyLocatorType.NONE, content.getKeyLocator().getType());

    // Check an encrypted content with IV.
    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    EncryptedContent rsaOaepContent = new EncryptedContent();
    rsaOaepContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(new Blob(message, false))
      .setInitialVector(new Blob(iv, false));

    assertEquals(EncryptAlgorithmType.RsaOaep, rsaOaepContent.getAlgorithmType());
    assertTrue(rsaOaepContent.getPayload().equals(new Blob(message, false)));
    assertTrue(rsaOaepContent.getInitialVector().equals(new Blob(iv, false)));
    assertTrue(rsaOaepContent.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(rsaOaepContent.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    // Encoding.
    Blob encryptedBlob = new Blob(encrypted, false);
    Blob encoded = rsaOaepContent.wireEncode();

    assertTrue(encryptedBlob.equals(encoded));

    // Decoding.
    EncryptedContent rsaOaepContent2 = new EncryptedContent();
    rsaOaepContent2.wireDecode(encryptedBlob);
    assertEquals(EncryptAlgorithmType.RsaOaep, rsaOaepContent2.getAlgorithmType());
    assertTrue(rsaOaepContent2.getPayload().equals(new Blob(message, false)));
    assertTrue(rsaOaepContent2.getInitialVector().equals(new Blob(iv, false)));
    assertTrue(rsaOaepContent2.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(rsaOaepContent2.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    // Check the no IV case.
    EncryptedContent rsaOaepContentNoIv = new EncryptedContent();
    rsaOaepContentNoIv.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(new Blob(message, false));
    assertEquals(EncryptAlgorithmType.RsaOaep, rsaOaepContentNoIv.getAlgorithmType());
    assertTrue(rsaOaepContentNoIv.getPayload().equals(new Blob(message, false)));
    assertTrue(rsaOaepContentNoIv.getInitialVector().isNull());
    assertTrue(rsaOaepContentNoIv.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(rsaOaepContentNoIv.getKeyLocator().getKeyName().equals
               (new Name("/test/key/locator")));

    // Encoding.
    Blob encryptedBlob2 = new Blob(encryptedNoIv, false);
    Blob encodedNoIV = rsaOaepContentNoIv.wireEncode();
    assertTrue(encryptedBlob2.equals(encodedNoIV));

    // Decoding.
    EncryptedContent rsaOaepContentNoIv2 = new EncryptedContent();
    rsaOaepContentNoIv2.wireDecode(encryptedBlob2);
    assertEquals(EncryptAlgorithmType.RsaOaep, rsaOaepContentNoIv2.getAlgorithmType());
    assertTrue(rsaOaepContentNoIv2.getPayload().equals(new Blob(message, false)));
    assertTrue(rsaOaepContentNoIv2.getInitialVector().isNull());
    assertTrue(rsaOaepContentNoIv2.getKeyLocator().getType() != KeyLocatorType.NONE);
    assertTrue(rsaOaepContentNoIv2.getKeyLocator().getKeyName().equals
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
    assertEquals(EncryptAlgorithmType.NONE, content.getAlgorithmType());
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

    content.setPayload(new Blob(message, false));
    assertTrue(content.getPayload().equals(new Blob(message, false)));

    content.setInitialVector(new Blob(iv, false));
    assertTrue(content.getInitialVector().equals(new Blob(iv, false)));

    Blob encoded = content.wireEncode();
    Blob contentBlob = new Blob(encrypted, false);
    assertTrue(contentBlob.equals(encoded));
  }
}