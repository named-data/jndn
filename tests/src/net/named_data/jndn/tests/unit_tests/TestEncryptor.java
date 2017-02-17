/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/encryptor.t.cpp
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.encrypt.algo.Encryptor;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestEncryptor {
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

  public interface SymmetricEncryptInput
  {
    String testName();
    Name keyName();
    EncryptParams encryptParams();
    Blob plainText();
    Blob key();
    Blob encryptedContent();
  };

  static class TestDataAesEcb implements SymmetricEncryptInput {
    public String testName() { return "TestDataAesEcb"; }
    public Name keyName() { return new Name("/test"); }
    public EncryptParams encryptParams() {
      return new EncryptParams(EncryptAlgorithmType.AesEcb);
    }
    public Blob plainText() {
      return new Blob(toBuffer(new int[] {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
      }), false);
    }
    public Blob key() {
      return new Blob(toBuffer(new int[] {
        0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
        0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
      }), false);
    }
    public Blob encryptedContent() {
      return new Blob(toBuffer(new int[] {
        0x82, 0x2f,
          0x1c, 0x08,
            0x07, 0x06,
              0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
          0x83, 0x01,
            0x00,
          0x84, 0x20,
            0x13, 0x80, 0x1a, 0xc0, 0x4c, 0x75, 0xa7, 0x7f,
            0x43, 0x5e, 0xd7, 0xa6, 0x3f, 0xd3, 0x68, 0x94,
            0xe2, 0xcf, 0x54, 0xb1, 0xc2, 0xce, 0xad, 0x9b,
            0x56, 0x6e, 0x1c, 0xe6, 0x55, 0x1d, 0x79, 0x04
      }), false);
    }
  };

  static class TestDataAesCbc implements SymmetricEncryptInput
  {
    public String testName() { return "TestDataAesCbc"; }
    public Name keyName() { return new Name("/test"); }
    public EncryptParams encryptParams() {
      return new EncryptParams(EncryptAlgorithmType.AesCbc)
        .setInitialVector(new Blob(toBuffer(new int[] {
          0x73, 0x6f, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x64,
          0x6f, 0x6d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72
        }), false));
    }
    public Blob plainText() {
      return new Blob(toBuffer(new int[] {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
      }), false);
    }
    public Blob key() {
      return new Blob(toBuffer(new int[] {
        0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
        0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
      }), false);
    }
    public Blob encryptedContent() {
      return new Blob(toBuffer(new int[] {
        0x82, 0x41, // EncryptedContent
          0x1c, 0x08, // KeyLocator /test
            0x07, 0x06,
              0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
          0x83, 0x01, // EncryptedAlgorithm
            0x01, // AlgorithmAesCbc
          0x85, 0x10,
            0x73, 0x6f, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x64,
            0x6f, 0x6d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72,
          0x84, 0x20, // EncryptedPayLoad
            0x6a, 0x6b, 0x58, 0x9c, 0x30, 0x3b, 0xd9, 0xa6,
            0xed, 0xd2, 0x12, 0xef, 0x29, 0xad, 0xc3, 0x60,
            0x1f, 0x1b, 0x6b, 0xc7, 0x03, 0xff, 0x53, 0x52,
            0x82, 0x6d, 0x82, 0x73, 0x05, 0xf9, 0x03, 0xdc
      }), false);
    }
  };

  SymmetricEncryptInput[] encryptorAesTestInputs = new SymmetricEncryptInput[]
    { new TestDataAesEcb(), new TestDataAesCbc() };

  @Test
  public void
  testContentSymmetricEncrypt()
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      EncodingException, NoSuchAlgorithmException, EncodingException, EncodingException
  {
    for (SymmetricEncryptInput input : encryptorAesTestInputs) {
      Data data = new Data();
      Encryptor.encryptData
        (data, input.plainText(), input.keyName(), input.key(), input.encryptParams());

      assertEquals
        (input.testName(), new Name("/FOR").append(input.keyName()), data.getName());

      assertTrue(input.testName(), input.encryptedContent().equals(data.getContent()));

      EncryptedContent content = new EncryptedContent();
      content.wireDecode(data.getContent());
      Blob decryptedOutput = AesAlgorithm.decrypt
        (input.key(), content.getPayload(), input.encryptParams());

      assertTrue(input.testName(), input.plainText().equals(decryptedOutput));
    }
  }

  public interface AsymmetricEncryptInput
  {
    String testName();
    EncryptAlgorithmType type();
  };

  static class TestDataRsaOaep implements AsymmetricEncryptInput {
    public String testName() { return "TestDataRsaOaep"; }
    public EncryptAlgorithmType type() { return EncryptAlgorithmType.RsaOaep; }
  };

  static class TestDataRsaPkcs implements AsymmetricEncryptInput {
    public String testName() { return "TestDataRsaPkcs"; }
    public EncryptAlgorithmType type() { return EncryptAlgorithmType.RsaPkcs; }
  };

  AsymmetricEncryptInput[] encryptorRsaTestInputs = new AsymmetricEncryptInput[]
    { new TestDataRsaOaep(), new TestDataRsaPkcs() };

  @Test
  public void
  testContentAsymmetricEncryptSmall()
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      DerDecodingException, EncodingException
  {
    for (AsymmetricEncryptInput input : encryptorRsaTestInputs) {
      Blob rawContent = new Blob(toBuffer(new int[] {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
      }), false);

      Data data = new Data();
      RsaKeyParams rsaParams = new RsaKeyParams(1024);

      Name keyName = new Name("test");

      DecryptKey decryptKey = RsaAlgorithm.generateKey(rsaParams);
      EncryptKey encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

      Blob eKey = encryptKey.getKeyBits();
      Blob dKey = decryptKey.getKeyBits();

      EncryptParams encryptParams = new EncryptParams(input.type());

      Encryptor.encryptData(data, rawContent, keyName, eKey, encryptParams);

      assertEquals
        (input.testName(), new Name("/FOR").append(keyName), data.getName());

      EncryptedContent extractContent = new EncryptedContent();
      extractContent.wireDecode(data.getContent());
      assertEquals(input.testName(), keyName, extractContent.getKeyLocator().getKeyName());
      assertEquals(input.testName(), 0, extractContent.getInitialVector().size());
      assertEquals(input.testName(), input.type(), extractContent.getAlgorithmType());

      Blob recovered = extractContent.getPayload();
      Blob decrypted = RsaAlgorithm.decrypt(dKey, recovered, encryptParams);
      assertTrue(input.testName(), rawContent.equals(decrypted));
    }
  }

  @Test
  public void
  testContentAsymmetricEncryptLarge()
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      DerDecodingException, EncodingException
  {
    for (AsymmetricEncryptInput input : encryptorRsaTestInputs) {
      Blob largeContent = new Blob(toBuffer(new int[] {
        0x73, 0x5a, 0xbd, 0x47, 0x0c, 0xfe, 0xf8, 0x7d,
        0x2e, 0x17, 0xaa, 0x11, 0x6f, 0x23, 0xc5, 0x10,
        0x23, 0x36, 0x88, 0xc4, 0x2a, 0x0f, 0x9a, 0x72,
        0x54, 0x31, 0xa8, 0xb3, 0x51, 0x18, 0x9f, 0x0e,
        0x1b, 0x93, 0x62, 0xd9, 0xc4, 0xf5, 0xf4, 0x3d,
        0x61, 0x9a, 0xca, 0x05, 0x65, 0x6b, 0xc6, 0x41,
        0xf9, 0xd5, 0x1c, 0x67, 0xc1, 0xd0, 0xd5, 0x6f,
        0x7b, 0x70, 0xb8, 0x8f, 0xdb, 0x19, 0x68, 0x7c,
        0xe0, 0x2d, 0x04, 0x49, 0xa9, 0xa2, 0x77, 0x4e,
        0xfc, 0x60, 0x0d, 0x7c, 0x1b, 0x93, 0x6c, 0xd2,
        0x61, 0xc4, 0x6b, 0x01, 0xe9, 0x12, 0x28, 0x6d,
        0xf5, 0x78, 0xe9, 0x99, 0x0b, 0x9c, 0x4f, 0x90,
        0x34, 0x3e, 0x06, 0x92, 0x57, 0xe3, 0x7a, 0x8f,
        0x13, 0xc7, 0xf3, 0xfe, 0xf0, 0xe2, 0x59, 0x48,
        0x15, 0xb9, 0xdb, 0x77, 0x07, 0x1d, 0x6d, 0xb5,
        0x65, 0x17, 0xdf, 0x76, 0x6f, 0xb5, 0x43, 0xde,
        0x71, 0xac, 0xf1, 0x22, 0xbf, 0xb2, 0xe5, 0xd9,
        0x22, 0xf1, 0x67, 0x76, 0x71, 0x0c, 0xff, 0x99,
        0x7b, 0x94, 0x9b, 0x24, 0x20, 0x80, 0xe3, 0xcc,
        0x06, 0x4a, 0xed, 0xdf, 0xec, 0x50, 0xd5, 0x87,
        0x3d, 0xa0, 0x7d, 0x9c, 0xe5, 0x13, 0x10, 0x98,
        0x14, 0xc3, 0x90, 0x10, 0xd9, 0x25, 0x9a, 0x59,
        0xe9, 0x37, 0x26, 0xfd, 0x87, 0xd7, 0xf4, 0xf9,
        0x11, 0x91, 0xad, 0x5c, 0x00, 0x95, 0xf5, 0x2b,
        0x37, 0xf7, 0x4e, 0xb4, 0x4b, 0x42, 0x7c, 0xb3,
        0xad, 0xd6, 0x33, 0x5f, 0x0b, 0x84, 0x57, 0x7f,
        0xa7, 0x07, 0x73, 0x37, 0x4b, 0xab, 0x2e, 0xfb,
        0xfe, 0x1e, 0xcb, 0xb6, 0x4a, 0xc1, 0x21, 0x5f,
        0xec, 0x92, 0xb7, 0xac, 0x97, 0x75, 0x20, 0xc9,
        0xd8, 0x9e, 0x93, 0xd5, 0x12, 0x7a, 0x64, 0xb9,
        0x4c, 0xed, 0x49, 0x87, 0x44, 0x5b, 0x4f, 0x90,
        0x34, 0x3e, 0x06, 0x92, 0x57, 0xe3, 0x7a, 0x8f,
        0x13, 0xc7, 0xf3, 0xfe, 0xf0, 0xe2, 0x59, 0x48,
        0x15, 0xb9, 0xdb, 0x77, 0x07, 0x1d, 0x6d, 0xb5,
        0x65, 0x17, 0xdf, 0x76, 0x6f, 0xb5, 0x43, 0xde,
        0x71, 0xac, 0xf1, 0x22, 0xbf, 0xb2, 0xe5, 0xd9
      }), false);

      Data data = new Data();
      RsaKeyParams rsaParams = new RsaKeyParams(1024);

      Name keyName = new Name("test");

      DecryptKey decryptKey = RsaAlgorithm.generateKey(rsaParams);
      EncryptKey encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

      Blob eKey = encryptKey.getKeyBits();
      Blob dKey = decryptKey.getKeyBits();

      EncryptParams encryptParams = new EncryptParams(input.type());
      Encryptor.encryptData(data, largeContent, keyName, eKey, encryptParams);

      assertEquals
        (input.testName(), new Name("/FOR").append(keyName), data.getName());

      Blob largeDataContent = data.getContent();

      // largeDataContent is a sequence of the two EncryptedContent.
      EncryptedContent encryptedNonce = new EncryptedContent();
      encryptedNonce.wireDecode(largeDataContent);
      assertEquals(input.testName(),
                   keyName, encryptedNonce.getKeyLocator().getKeyName());
      assertEquals(input.testName(), 0, encryptedNonce.getInitialVector().size());
      assertEquals(input.testName(), input.type(), encryptedNonce.getAlgorithmType());

      // Use the size of encryptedNonce to find the start of encryptedPayload.
      ByteBuffer payloadContent = largeDataContent.buf().duplicate();
      payloadContent.position(encryptedNonce.wireEncode().size());
      EncryptedContent encryptedPayload = new EncryptedContent();
      encryptedPayload.wireDecode(payloadContent);
      Name nonceKeyName = new Name(keyName);
      nonceKeyName.append("nonce");
      assertEquals(input.testName(),
                   nonceKeyName, encryptedPayload.getKeyLocator().getKeyName());
      assertEquals(input.testName(),
                   16, encryptedPayload.getInitialVector().size());
      assertEquals(input.testName(),
                   EncryptAlgorithmType.AesCbc, encryptedPayload.getAlgorithmType());

      assertTrue(input.testName(), encryptedNonce.wireEncode().size() +
                 encryptedPayload.wireEncode().size() ==
                 largeDataContent.size());

      Blob blobNonce = encryptedNonce.getPayload();
      Blob nonce = RsaAlgorithm.decrypt(dKey, blobNonce, encryptParams);

      encryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
      encryptParams.setInitialVector(encryptedPayload.getInitialVector());
      Blob bufferPayload = encryptedPayload.getPayload();
      Blob largePayload = AesAlgorithm.decrypt
        (nonce, bufferPayload, encryptParams);

      assertTrue(input.testName(), largeContent.equals(largePayload));
    }
  }
}