/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Andrew Brown
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
import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.identity.FilePrivateKeyStorage;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class TestFilePrivateKeyStorage {

  /**
   * Keep a reference to the key storage folder
   */
  private static final File ndnFolder_ = new File (new File(Common.getHomeDirectory(), ".ndn"), "ndnsec-tpm-file");;

  /**
   * Create a few keys before testing
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception {
    // create some test key files to use in tests
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/123"), new RsaKeyParams(2048));
  }

  /**
   * Delete the keys we created
   */
  @AfterClass
  public static void tearDownClass() {
    // delete all keys when done
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    try{
      instance.deleteKey(new Name("/test/KEY/123"));
    }
    catch(Exception e){
      System.err.println("Failed to clean up generated keys");
    }

    try {
      instance.deleteKey(new Name("/test/KEY/temp1"));
    }
    catch (Exception e) {
      // Not all tests create this key so ignore if we don't delete it.
    }
  }

  /**
   * Convert the int array to a ByteBuffer.
   * @param array
   * @return
   */
  private static ByteBuffer toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  /**
   * Test of generateKeyPair method, of class FilePrivateKeyStorage.
   */
  @Test
  public void testGenerateAndDeleteKeys() throws Exception {
    // create some more key files
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/temp1"), new RsaKeyParams(2048));
    // check if files created
    File[] files = ndnFolder_.listFiles();
    int createdFileCount = files.length;
    assertTrue(createdFileCount >= 2); // 2 pre-created + 2 created now + some created by NFD
    // delete these keys
    instance.deleteKey(new Name("/test/KEY/temp1"));
    files = ndnFolder_.listFiles();
    int deletedfileCount = files.length;
    assertTrue(createdFileCount - 2 == deletedfileCount);
  }

  /**
   * Test of doesKeyExist method, of class FilePrivateKeyStorage.
   */
  @Test
  public void testDoesKeyExist() throws Exception {
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    assertTrue(instance.doesKeyExist(new Name("/test/KEY/123"), KeyClass.PRIVATE));
    assertFalse(instance.doesKeyExist(new Name("/unknown"), KeyClass.PRIVATE));
  }

  /**
   * Test of getPublicKey method, of class FilePrivateKeyStorage.
   */
  @Test
  public void testGetPublicKey() throws Exception {
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    PublicKey result = instance.getPublicKey(new Name("/test/KEY/123"));
    assertNotNull(result);
  }

  /**
   * Test of sign method, of class FilePrivateKeyStorage.
   */
  @Test
  public void testSign() throws Exception {
    int[] data = new int[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    Blob result = instance.sign(toBuffer(data), new Name("/test/KEY/123"), DigestAlgorithm.SHA256);
    assertNotNull(result);
  }
}
