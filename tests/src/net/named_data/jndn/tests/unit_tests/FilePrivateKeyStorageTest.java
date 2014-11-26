/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.named_data.jndn.tests.unit_tests;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.identity.FilePrivateKeyStorage;
import net.named_data.jndn.util.Blob;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author abrown
 */
public class FilePrivateKeyStorageTest {
  
  private static File ndnFolder_ = new File (new File(System.getProperty("user.home", "."), ".ndn"), "ndnsec-tpm-file");;
  
  public FilePrivateKeyStorageTest() {
  }
  
  @BeforeClass
  public static void setUpClass() throws Exception {
    // create some test key files to use in tests
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/123"), KeyType.RSA, 2048);
  }
  
  @AfterClass
  public static void tearDownClass() {
    // delete all keys when done
    File[] files = ndnFolder_.listFiles();
    if(files != null){
      for(File f : files){
        f.delete();
      }
    }
  }
  
  @Before
  public void setUp() {

  }
  
  @After
  public void tearDown() {
  }
  
  // Convert the int array to a ByteBuffer.
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
  public void testGenerateKeys() throws Exception {
    // create some more key files
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/456"), KeyType.RSA, 2048);
    instance.generateKey(new Name("/test/KEY/789"), KeyType.AES, 256);
    // check if files created
    File[] files = ndnFolder_.listFiles();
    System.out.print("Files created by generateKeyPair(): ");
    for(File f : files){ System.out.print(f + ", "); }
    System.out.println();
    assertEquals(5, files.length); // 2 pre-created + 3 created now
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

  /**
   * Test encrypt/decrypt methods, of class FilePrivateKeyStorage.
   */
  @Test
  public void testAsymmetricEncryptAndDecrypt() throws Exception {
    byte[] plaintext = "Some text...".getBytes();
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    // encrypt
    Blob encrypted = instance.encrypt(new Name("/test/KEY/123"), ByteBuffer.wrap(plaintext), false);
    assertNotNull(encrypted);
    assertFalse(Arrays.equals(plaintext, encrypted.getImmutableArray()));
    // decrypt
    Blob encryptedCopy = new Blob(encrypted.getImmutableArray()); // copy bytes because decrypt tries to modify them
    Blob decrypted = instance.decrypt(new Name("/test/KEY/123"), encryptedCopy.buf(), false);
    assertNotNull(decrypted);
    assertTrue(Arrays.equals(plaintext, decrypted.getImmutableArray()));
  } 
}
