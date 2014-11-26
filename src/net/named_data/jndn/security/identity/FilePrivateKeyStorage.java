/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.security.identity;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * FilePrivateKeyStorage extends PrivateKeyStorage to implement private key
 * storage using files.
 */
public class FilePrivateKeyStorage extends PrivateKeyStorage { 
  /**
   * Create a new FilePrivateKeyStorage to connect to the default directory.
   */
  public FilePrivateKeyStorage()
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    keyStorePath_ = new File
      (new File(System.getProperty("user.home", "."), ".ndn"), "ndnsec-tpm-file");
    keyStorePath_.mkdirs();
  }

  /**
   * Generate a pair of asymmetric keys.
   * @param keyName The name of the key pair.
   * @param keyType The type of the key pair, e.g. KeyType.RSA.
   * @param keySize The size of the key pair.
   * @throws SecurityException
   */
  public final void
  generateKeyPair
    (Name keyName, KeyType keyType, int keySize) throws SecurityException
  {
    KeyPairGenerator generator = null;
    try{
      generator = KeyPairGenerator.getInstance(keyType.toString());
    }
    catch(NoSuchAlgorithmException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Could not create the key generator: " + e.getMessage());
    }
    
    // generate
    generator.initialize(keySize);
    KeyPair pair = generator.generateKeyPair();
    
    // save
    this.write(keyName, KeyClass.PRIVATE, pair.getPrivate().getEncoded());
    this.write(keyName, KeyClass.PUBLIC, pair.getPublic().getEncoded());
  }

  /**
   * Get the public key
   * @param keyName The name of public key.
   * @return The public key.
   * @throws SecurityException
   */
  public final PublicKey
  getPublicKey(Name keyName) throws SecurityException
  {
    if (!doesKeyExist(keyName, KeyClass.PUBLIC))
      throw new SecurityException("Public key does not exist.");

    // Read the file contents.
    byte[] der = this.read(keyName, KeyClass.PUBLIC);

    // TODO: Don't assume keyType is RSA.
    return PublicKey.fromDer(KeyType.RSA, new Blob(der));
  }
  
  /**
   * Get the private key for this name; internal helper method
   * @param keyName
   * @return
   * @throws SecurityException 
   */
  private final PrivateKey
  getPrivateKey(Name keyName) throws SecurityException
  {
    if (!doesKeyExist(keyName, KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage: Private key does not exist.");

    // Read the file contents.
    byte[] der = this.read(keyName, KeyClass.PRIVATE);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    try{
      // TODO: Check the key type. Don't assume RSA.
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(spec);
    }
    catch(InvalidKeySpecException e){
      // Don't expect this to happen.
      throw new SecurityException
        ("FilePrivateKeyStorage: RSA is not supported: " + e.getMessage());
    }
    catch(NoSuchAlgorithmException e){
      // Don't expect this to happen.
      throw new SecurityException
        ("FilePrivateKeyStorage: PKCS8EncodedKeySpec is not supported for RSA: " 
                + e.getMessage());
    }
  }
  
  /**
   * Get the symmetric key for this name; internal helper method
   * @param keyName
   * @return
   * @throws SecurityException 
   */
  private final SecretKey
  getSymmetricKey(Name keyName) throws SecurityException
  {
    if (!doesKeyExist(keyName, KeyClass.SYMMETRIC))
      throw new SecurityException
        ("FilePrivateKeyStorage: Symmetric key does not exist.");

    // Read the file contents.
    byte[] encoded = this.read(keyName, KeyClass.SYMMETRIC);
    // TODO: Check the key type. Don't assume AES.
    return new SecretKeySpec(encoded, "AES");
  }


  /**
   * Fetch the private key for keyName and sign the data, returning a signature
   * Blob.
   * @param data Pointer the input byte buffer to sign.
   * @param keyName The name of the signing key.
   * @param digestAlgorithm the digest algorithm.
   * @return The signature, or a null pointer if signing fails.
   * @throws SecurityException
   */
  public final Blob
  sign(ByteBuffer data, Name keyName, DigestAlgorithm digestAlgorithm)
      throws SecurityException
  {
    if (!doesKeyExist(keyName, KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage.sign: private key doesn't exist");

    if (digestAlgorithm != DigestAlgorithm.SHA256)
      throw new SecurityException
        ("FilePrivateKeyStorage.sign: Unsupported digest algorithm");

    // Retrieve the private key.
    PrivateKey privateKey = this.getPrivateKey(keyName);

    // Sign.
    Signature signature = null;
    // TODO: Check the key type. Don't assume RSA.
    try {
      signature = Signature.getInstance("SHA256withRSA");
    }
    catch (NoSuchAlgorithmException e) {
      // Don't expect this to happen.
      throw new SecurityException("FilePrivateKeyStorage: SHA256withRSA algorithm is not supported");
    }

    try {
      signature.initSign(privateKey);
    }
    catch (InvalidKeyException exception) {
      throw new SecurityException
        ("FilePrivateKeyStorage: InvalidKeyException: " + exception.getMessage());
    }
    try {
      signature.update(data);
      return new Blob(signature.sign());
    }
    catch (SignatureException exception) {
      throw new SecurityException
        ("FilePrivateKeyStorage: SignatureException: " + exception.getMessage());
    }
  }
  
  /**
   * Decrypt data.
   * @param keyName The name of the decrypting key.
   * @param data The byte buffer to be decrypted, from its position to its
   * limit.
   * @param isSymmetric If true symmetric encryption is used, otherwise
   * asymmetric encryption is used.
   * @return The decrypted data.
   * @throws SecurityException
   */
  public final Blob
  decrypt(Name keyName, ByteBuffer data, boolean isSymmetric)
         throws SecurityException
  {
    if (!doesKeyExist(keyName, isSymmetric ? KeyClass.SYMMETRIC : KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage.decrypt: key doesn't exist");
    
    Key key = isSymmetric ? this.getSymmetricKey(keyName) 
            : this.getPrivateKey(keyName);
    
    Cipher cipher = null;
    String cipherAlgorithm = isSymmetric ? "AES" : "RSA"; // TODO don't assume
    try{
      cipher = Cipher.getInstance(cipherAlgorithm);
    }
    catch(NoSuchAlgorithmException | NoSuchPaddingException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.decrypt: can't start Cipher: " 
                + e.getMessage());
    }
    
    try{
      cipher.init(Cipher.DECRYPT_MODE, key);
    }
    catch(InvalidKeyException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.decrypt: invalid key: " + e.getMessage());
    }
    
    try{
      // allocate a new ByteBuffer because data is read-only
      ByteBuffer decrypted = ByteBuffer.allocate(cipher.getOutputSize(data.limit()));
      cipher.doFinal(data, decrypted);
      decrypted.flip(); // otherwise bytes are reversed
      return new Blob(decrypted, true);
    }
    catch(BadPaddingException | ShortBufferException |
            IllegalBlockSizeException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.decrypt: " + e.getMessage());
    }
  }

  /**
   * Encrypt data.
   * @param keyName The name of the encrypting key.
   * @param data The byte buffer to be encrypted, from its position to its
   * limit.
   * @param isSymmetric If true symmetric encryption is used, otherwise
   * asymmetric encryption is used.
   * @return The encrypted data.
   * @throws SecurityException
   */
  public final Blob
  encrypt(Name keyName, ByteBuffer data, boolean isSymmetric)
          throws SecurityException
  {
    if (!doesKeyExist(keyName, isSymmetric ? KeyClass.SYMMETRIC : KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage.encrypt: key doesn't exist");
    
    Key key = isSymmetric ? this.getSymmetricKey(keyName) 
            : this.getPrivateKey(keyName);
    
    Cipher cipher = null;
    String cipherAlgorithm = isSymmetric ? "AES" : "RSA"; // TODO don't assume
    try{
      cipher = Cipher.getInstance(cipherAlgorithm);
    }
    catch(NoSuchAlgorithmException | NoSuchPaddingException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.encrypt: can't start Cipher: " 
                + e.getMessage());
    }
    
    try{
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }
    catch(InvalidKeyException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.encrypt: invalid key: " 
                + e.getMessage());
    }
    
    try{
      byte[] encrypted = cipher.doFinal(data.array());
      return new Blob(encrypted);
    }
    catch(BadPaddingException | IllegalBlockSizeException e){
      throw new SecurityException
        ("FilePrivateKeyStorage.encrypt: invalid input ByteBuffer: " 
                + e.getMessage());
    }
  }

  /**
   * Generate a symmetric key.
   * @param keyName The name of the key.
   * @param keyType The type of the key, e.g. KeyType.AES.
   * @param keySize The size of the key.
   * @throws SecurityException
   */
  public final void
  generateKey(Name keyName, KeyType keyType, int keySize)
             throws SecurityException
  {
    KeyGenerator generator = null;
    try{
      generator = KeyGenerator.getInstance(keyType.toString());
    }
    catch(NoSuchAlgorithmException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Could not create the key generator: " + e.getMessage());
    }
    
    // generate...
    generator.init(keySize);
    SecretKey key = generator.generateKey();
    
    // ... and save
    this.write(keyName, KeyClass.SYMMETRIC, key.getEncoded());
  }
    
  /**
   * Check if a particular key exists.
   * @param keyName The name of the key.
   * @param keyClass The class of the key, e.g. KeyClass.PUBLIC,
   * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
   * @return True if the key exists, otherwise false.
   */
  public final boolean
  doesKeyExist(Name keyName, KeyClass keyClass) throws SecurityException
  {
    String keyURI = keyName.toUri();
    String extension = (String) keyTypeMap_.get(keyClass);
    if(extension == null) throw new SecurityException("Unrecognized key class");
    else return nameTransform(keyURI, extension).exists();
  }

  /**
   * Transform a key name to its hashed file path
   * @param keyName
   * @param extension
   * @return
   * @throws SecurityException 
   */
  private File
  nameTransform(String keyName, String extension) throws SecurityException
  {
    MessageDigest sha256;
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new Error
        ("MessageDigest: SHA-256 is not supported: " + exception.getMessage());
    }
    sha256.update(keyName.getBytes());
    byte[] hash = sha256.digest();

    String digest = Common.base64Encode(hash);
    digest = digest.replace('/', '%');

    return new File(keyStorePath_, digest + extension);
  }
  
  /**
   * Write to a key file
   * @param keyName
   * @param keyClass [PUBLIC, PRIVATE, SYMMETRIC]
   * @param data
   * @throws IOException
   * @throws SecurityException 
   */
  private void
  write(Name keyName, KeyClass keyClass, byte[] data) throws SecurityException{
    String extension = (String) keyTypeMap_.get(keyClass);
    try{
      BufferedWriter writer = new BufferedWriter
        (new FileWriter(nameTransform(keyName.toUri(), extension)));
      try{
        String base64Data = Common.base64Encode(data);
        writer.write(base64Data, 0, base64Data.length());
        writer.flush();
      }
      finally{
        writer.close();
      }
    }
    catch(SecurityException | IOException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to write key: " + e.getMessage());
    }
  }
  
  /**
   * Read from a key file
   * @param keyName
   * @param keyClass [PUBLIC, PRIVATE, SYMMETRIC]
   * @return
   * @throws IOException
   * @throws SecurityException 
   */
  private byte[]
  read(Name keyName, KeyClass keyClass) throws SecurityException{
    String extension = (String) keyTypeMap_.get(keyClass);
    StringBuilder contents = new StringBuilder();
    try{
      BufferedReader reader = new BufferedReader
        (new FileReader(nameTransform(keyName.toUri(), extension)));
      // Use "try/finally instead of "try-with-resources" or "using" 
      // which are not supported before Java 7.
      try {
        String line = null;
        while ((line = reader.readLine()) != null)
          contents.append(line);
      } finally {
        reader.close();
      }
    }
    catch(SecurityException | IOException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to read key: " + e.getMessage());
    }
    return Common.base64Decode(contents.toString());
  }

  private final File keyStorePath_;
  private static final HashMap keyTypeMap_;
  static{
    keyTypeMap_ = new HashMap<KeyClass, String>();
    keyTypeMap_.put(KeyClass.PUBLIC, ".pub");
    keyTypeMap_.put(KeyClass.PRIVATE, ".pri");
    keyTypeMap_.put(KeyClass.SYMMETRIC, ".key");
  }
}
