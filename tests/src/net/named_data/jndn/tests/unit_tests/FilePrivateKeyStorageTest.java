/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.named_data.jndn.tests.unit_tests;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
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
    instance.generateKey(new Name("/test/KEY/456"), KeyType.AES, 128); // can't be greater than 128 without Java Crypto Extension (JCE)
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
    instance.generateKeyPair(new Name("/test/KEY/temp1"), KeyType.RSA, 2048);
    instance.generateKey(new Name("/test/KEY/temp2"), KeyType.AES, 128);
    // check if files created
    File[] files = ndnFolder_.listFiles();
    System.out.print("Files created by generateKeyPair(): ");
    for(File f : files){ System.out.print(f + ", "); }
    System.out.println();
    assertEquals(6, files.length); // 3 pre-created + 3 created now
  }
  
  /**
   * Test of doesKeyExist method, of class FilePrivateKeyStorage.
   */
  @Test
  public void testDoesKeyExist() throws Exception {
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    assertTrue(instance.doesKeyExist(new Name("/test/KEY/123"), KeyClass.PRIVATE));
    assertTrue(instance.doesKeyExist(new Name("/test/KEY/456"), KeyClass.SYMMETRIC));
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
    Blob decrypted = instance.decrypt(new Name("/test/KEY/123"), encrypted.buf(), false);
    assertNotNull(decrypted);
    assertTrue(Arrays.equals(plaintext, decrypted.getImmutableArray()));
  } 
  
  /**
   * Test encrypt/decrypt methods, of class FilePrivateKeyStorage.
   */
  @Test
  public void testSymmetricEncryptAndDecrypt() throws Exception {
    byte[] plaintext = "Some text...".getBytes();
    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
    // encrypt
    Blob encrypted = instance.encrypt(new Name("/test/KEY/456"), ByteBuffer.wrap(plaintext), true);
    assertNotNull(encrypted);
    assertFalse(Arrays.equals(plaintext, encrypted.getImmutableArray()));
    // decrypt
    Blob decrypted = instance.decrypt(new Name("/test/KEY/456"), encrypted.buf(), true);
    assertNotNull(decrypted);
    assertTrue(Arrays.equals(plaintext, decrypted.getImmutableArray()));
  } 
  
//  /**
//   * Verify key read/write work correctly; requires changing some methods
//   * to public
//   * @throws Exception 
//   */
//  @Test
//  public void testKeyGenerationWrite() throws Exception{
//    FilePrivateKeyStorage instance = new FilePrivateKeyStorage();
//    
//    // generate
//    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//    generator.initialize(1024);
//    KeyPair pair = generator.generateKeyPair();
//    
//    // write
//    Name name = new Name("/1/2/3");
//    instance.write(name, KeyClass.PRIVATE, pair.getPrivate().getEncoded());
//    instance.write(name, KeyClass.PUBLIC, pair.getPublic().getEncoded());
//    
//    // read
//    PublicKey publicKey = instance.getPublicKey(name);
//    PrivateKey privateKey = instance.getPrivateKey(name);
//    
//    assertTrue(Arrays.equals(pair.getPublic().getEncoded(), publicKey.getKeyDer().getImmutableArray()));
//    assertTrue(Arrays.equals(pair.getPrivate().getEncoded(), privateKey.getEncoded()));
//  }
}
