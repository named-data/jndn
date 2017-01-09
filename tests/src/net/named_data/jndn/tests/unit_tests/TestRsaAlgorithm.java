/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/rsa.t.cpp
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestRsaAlgorithm {
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

  private static final String PRIVATE_KEY =
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMLY2w1PmsuZNvZ4" +
    "rJs1pESLrxF1Xlk9Zg4Sc0r2HIEn/eme8f7cOxXq8OtxIjowEfjceHGvfc7YG1Nw" +
    "LDh+ka4Jh6QtYqPEL9GHfrBeufynd0g2PAPVXySBvOJr/Isk+4/Fsj5ihrIPgrQ5" +
    "wTBBuLYjDgwPppC/+vddsr5wu5bbAgMBAAECgYBYmRLB8riIa5q6aBTUXofbQ0jP" +
    "v3avTWPicjFKnK5JbE3gtQ2Evc+AH9x8smzF2KXTayy5RPsH2uxR/GefKK5EkWbB" +
    "mLwWDJ5/QPlLK1STxPs8B/89mp8sZkZ1AxnSHhV/a3dRcK1rVamVcqPMdFyM5PfX" +
    "/apL3MlL6bsq2FipAQJBAOp7EJuEs/qAjh8hgyV2acLdsokUEwXH4gCK6+KQW8XS" +
    "xFWAG4IbbLfq1HwEpHC2hJSzifCQGoPAxYBRgSK+h6sCQQDUuqF04o06+Qpe4A/W" +
    "pWCBGE33+CD4lBtaeoIagsAs/lgcFmXiJZ4+4PhyIORmwFgql9ZDFHSpl8rAYsfk" +
    "dz2RAkEAtUKpFe/BybYzJ3Galg0xuMf0ye7QvblExjKeIqiBqS1DRO0hVrSomIxZ" +
    "8f0MuWz+lI0t5t8fABa3FnjrINa0vQJBAJeZKNaTXPJZ5/oU0zS0RkG5gFbmjRiY" +
    "86VXCMC7zRhDaacajyDKjithR6yNpDdVe39fFWJYgYsakXLo8mruTwECQGqywoy9" +
    "epf1flKx4YCCrw+qRKmbkcXWcpFV32EG2K2D1GsxkuXv/b3qO67Uxx1Arxp9o8dl" +
    "k34WfzApRjNjho0=";

  private static final String PUBLIC_KEY =
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC2NsNT5rLmTb2eKybNaREi68R" +
    "dV5ZPWYOEnNK9hyBJ/3pnvH+3DsV6vDrcSI6MBH43Hhxr33O2BtTcCw4fpGuCYek" +
    "LWKjxC/Rh36wXrn8p3dINjwD1V8kgbzia/yLJPuPxbI+YoayD4K0OcEwQbi2Iw4M" +
    "D6aQv/r3XbK+cLuW2wIDAQAB";

  // plaintext: RSA-Encrypt-Test
  private static final ByteBuffer PLAINTEXT = toBuffer(new int[] {
    0x52, 0x53, 0x41, 0x2d, 0x45, 0x6e, 0x63, 0x72,
    0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
  });

  private static final ByteBuffer CIPHERTEXT_OAEP = toBuffer(new int[] {
    0x33, 0xfb, 0x32, 0xd4, 0x2d, 0x45, 0x75, 0x3f, 0x34, 0xde, 0x3b,
    0xaa, 0x80, 0x5f, 0x74, 0x6f, 0xf0, 0x3f, 0x01, 0x31, 0xdd, 0x2b,
    0x85, 0x02, 0x1b, 0xed, 0x2d, 0x16, 0x1b, 0x96, 0xe5, 0x77, 0xde,
    0xcd, 0x44, 0xe5, 0x3c, 0x32, 0xb6, 0x9a, 0xa9, 0x5d, 0xaa, 0x4b,
    0x94, 0xe2, 0xac, 0x4a, 0x4e, 0xf5, 0x35, 0x21, 0xd0, 0x03, 0x4a,
    0xa7, 0x53, 0xae, 0x13, 0x08, 0x63, 0x38, 0x2c, 0x92, 0xe3, 0x44,
    0x64, 0xbf, 0x33, 0x84, 0x8e, 0x51, 0x9d, 0xb9, 0x85, 0x83, 0xf6,
    0x8e, 0x09, 0xc1, 0x72, 0xb9, 0x90, 0x5d, 0x48, 0x63, 0xec, 0xd0,
    0xcc, 0xfa, 0xab, 0x44, 0x2b, 0xaa, 0xa6, 0xb6, 0xca, 0xec, 0x2b,
    0x5f, 0xbe, 0x77, 0xa5, 0x52, 0xeb, 0x0a, 0xaa, 0xf2, 0x2a, 0x19,
    0x62, 0x80, 0x14, 0x87, 0x42, 0x35, 0xd0, 0xb6, 0xa3, 0x47, 0x4e,
    0xb6, 0x1a, 0x88, 0xa3, 0x16, 0xb2, 0x19
  });

  private static final ByteBuffer CIPHERTEXT_PKCS = toBuffer(new int[] {
    0xaf, 0x64, 0xf0, 0x12, 0x87, 0xcb, 0x29, 0x02, 0x8b, 0x3e, 0xb2,
    0xca, 0xfd, 0xf1, 0xcc, 0xef, 0x1e, 0xab, 0xb5, 0x6e, 0x4b, 0xa8,
    0x3b, 0x28, 0xb4, 0x3d, 0x9d, 0x49, 0xb1, 0xc5, 0xad, 0x44, 0xad,
    0x75, 0x5c, 0x18, 0x6b, 0x71, 0x4a, 0xbc, 0xf0, 0x73, 0xeb, 0xf6,
    0x4d, 0x0a, 0x37, 0xaa, 0xfe, 0x77, 0x1d, 0xc4, 0x43, 0xfa, 0xb1,
    0x2d, 0x59, 0xe6, 0xd9, 0x2e, 0xf2, 0x2f, 0xd5, 0x48, 0x4b, 0x8b,
    0x44, 0x94, 0xf9, 0x94, 0x92, 0x38, 0x82, 0x22, 0x41, 0x57, 0xbf,
    0xf9, 0x2c, 0xd8, 0x00, 0xb4, 0x68, 0x3c, 0xdd, 0xf2, 0xe4, 0xc8,
    0x64, 0x69, 0x05, 0x41, 0x58, 0x7c, 0x75, 0x68, 0x12, 0x98, 0x7b,
    0x87, 0x22, 0x0f, 0x38, 0x25, 0x5c, 0xf3, 0x36, 0x94, 0x86, 0x98,
    0x30, 0x68, 0x0d, 0x44, 0xa4, 0x52, 0x73, 0x2a, 0x62, 0xf2, 0xf0,
    0x15, 0xee, 0x94, 0x46, 0xc9, 0x7a, 0x52
  });

  @Test
  public void
  testEncryptionDecryption()
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException, DerDecodingException
  {
    EncryptParams encryptParams = new EncryptParams
      (EncryptAlgorithmType.RsaOaep, 0);

    Blob privateKeyBlob = new Blob(Common.base64Decode(PRIVATE_KEY), false);
    Blob publicKeyBlob = new Blob(Common.base64Decode(PUBLIC_KEY), false);

    DecryptKey decryptKey = new DecryptKey(privateKeyBlob);
    EncryptKey encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

    Blob encodedPublic = publicKeyBlob;
    Blob derivedPublicKey = encryptKey.getKeyBits();

    assertTrue(encodedPublic.equals(derivedPublicKey));

    Blob plainBlob = new Blob(PLAINTEXT, false);
    Blob encryptBlob = RsaAlgorithm.encrypt
      (encryptKey.getKeyBits(), plainBlob, encryptParams);
    Blob receivedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), encryptBlob, encryptParams);

    assertTrue(plainBlob.equals(receivedBlob));

    Blob cipherBlob = new Blob(CIPHERTEXT_OAEP, false);
    Blob decryptedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), cipherBlob, encryptParams);

    assertTrue(plainBlob.equals(decryptedBlob));

    // Now test RsaPkcs.
    encryptParams = new EncryptParams(EncryptAlgorithmType.RsaPkcs, 0);
    encryptBlob = RsaAlgorithm.encrypt
      (encryptKey.getKeyBits(), plainBlob, encryptParams);
    receivedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), encryptBlob, encryptParams);

    assertTrue(plainBlob.equals(receivedBlob));

    cipherBlob = new Blob(CIPHERTEXT_PKCS, false);
    decryptedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), cipherBlob, encryptParams);

    assertTrue(plainBlob.equals(decryptedBlob));
  }
}