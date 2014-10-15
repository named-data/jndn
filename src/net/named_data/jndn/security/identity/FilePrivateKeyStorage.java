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
import java.io.FileReader;
import java.io.IOException;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;

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
    throw new Error("FilePrivateKeyStorage.generateKeyPair not implemented");
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
    String keyURI = keyName.toUri();

    if (!doesKeyExist(keyName, KeyClass.PUBLIC))
      throw new SecurityException("Public Key does not exist.");

    // Read the file contents.
    StringBuilder contents = new StringBuilder();
    try {
      BufferedReader reader = new BufferedReader
        (new FileReader(nameTransform(keyURI, ".pub")));
      // Use "try/finally instead of "try-with-resources" or "using" which are not supported before Java 7.
      try {
        String line = null;
        while ((line = reader.readLine()) != null)
          contents.append(line);
      } finally {
        reader.close();
      }
    } catch (IOException exception) {
      throw new SecurityException("FilePrivateKeyStorage: IO error: " + exception);
    }

    byte[] der = base64Decode(contents.toString());

    // TODO: Need to get the correct keyType.
    return PublicKey.fromDer(KeyType.RSA, new Blob(der));
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
    String keyURI = keyName.toUri();

    if (!doesKeyExist(keyName, KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage.sign: private key doesn't exist");

    if (digestAlgorithm != DigestAlgorithm.SHA256)
      throw new SecurityException
        ("FilePrivateKeyStorage.sign: Unsupported digest algorithm");

    // Read the private key.
    StringBuilder contents = new StringBuilder();
    try {
      BufferedReader reader = new BufferedReader
        (new FileReader(nameTransform(keyURI, ".pri")));
      try {
        String line = null;
        while ((line = reader.readLine()) != null)
          contents.append(line);
      } finally {
        reader.close();
      }
    } catch (IOException exception) {
      throw new SecurityException("FilePrivateKeyStorage: IO error: " + exception);
    }

    byte[] der = base64Decode(contents.toString());

    // TODO: Check the key type. Don't assume RSA.
    PrivateKey privateKey = null;
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("FilePrivateKeyStorage: RSA is not supported: " + exception.getMessage());
    }

    try {
      privateKey =
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("FilePrivateKeyStorage: PKCS8EncodedKeySpec is not supported for RSA: " +
         exception.getMessage());
    }

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
    throw new Error("FilePrivateKeyStorage.decrypt not implemented");
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
    throw new Error("FilePrivateKeyStorage.encrypt not implemented");
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
    throw new Error("FilePrivateKeyStorage.generateKey not implemented");
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
    if (keyClass == KeyClass.PUBLIC)
      return nameTransform(keyURI, ".pub").exists();
    else if (keyClass == KeyClass.PRIVATE)
      return nameTransform(keyURI, ".pri").exists();
    else if (keyClass == KeyClass.SYMMETRIC)
      return nameTransform(keyURI, ".key").exists();
    else
      return false;
  }

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

    String digest = base64Encode(hash);
    digest = digest.replace('/', '%');

    return new File(keyStorePath_, digest + extension);
  }

  private enum Base64ConverterType {
    UNINITIALIZED, JAVAX, ANDROID, UNSUPPORTED
  }

  /**
   * If not already initialized, set base64Converter_ to the correct loaded
   * class and set base64ConverterType_ to the loaded type.
   * If base64ConverterType_ is UNINITIALIZED, set base64Converter_ to
   * the class for javax.xml.bind.DatatypeConverter and set
   * base64ConverterType_ to JAVAX.  Else try to set base64Converter_ to
   * the class for android.util.Base64 and set base64ConverterType_ to ANDROID.
   * If these fail, set base64ConverterType_ to UNSUPPORTED and throw an
   * SecurityException from now on.
   */
  private static void
  establishBase64Converter() throws SecurityException
  {
    if (base64ConverterType_ == Base64ConverterType.UNINITIALIZED) {
      try {
        base64Converter_ = Class.forName("javax.xml.bind.DatatypeConverter");
        base64ConverterType_ = Base64ConverterType.JAVAX;
        return;
      } catch (ClassNotFoundException ex) {}

      try {
        base64Converter_ = Class.forName("android.util.Base64");
        base64ConverterType_ = Base64ConverterType.ANDROID;
        return;
      } catch (ClassNotFoundException ex) {}

      base64ConverterType_ = Base64ConverterType.UNSUPPORTED;
    }

   if (base64ConverterType_ == Base64ConverterType.UNSUPPORTED)
      throw new SecurityException
        ("establishBase64Converter: Cannot load a Base64 converter");
  }

  /**
   * Encode the input as base64 using the appropriate base64Converter_ from
   * establishBase64Converter(), for ANDROID or Java 7+.
   * @param input The bytes to encode.
   * @return The base64 string.
   * @throws SecurityException If can't establish a base64 converter for
   * this platform.
   */
  public static String
  base64Encode(byte[] input) throws SecurityException
  {
    establishBase64Converter();

    try {
      if (base64ConverterType_ == Base64ConverterType.ANDROID)
        // Base64.NO_WRAP  is 2.
        return (String)base64Converter_.getDeclaredMethod
          ("encodeToString", byte[].class, int.class).invoke(null, input, 2);
      else
        // Default to Base64ConverterType.JAVAX.
        return (String)base64Converter_.getDeclaredMethod
          ("printBase64Binary", byte[].class).invoke(null, input);
    } catch (Exception ex) {
      throw new SecurityException("base64Encode: Error invoking method: " + ex);
    }
  }

  /**
   * Decode the input as base64 using the appropriate base64Converter_ from
   * establishBase64Converter(), for ANDROID or Java 7+.
   * @param encoding The base64 string.
   * @return The decoded bytes.
   * @throws SecurityException If can't establish a base64 converter for
   * this platform.
   */
  public static byte[]
  base64Decode(String encoding) throws SecurityException
  {
    establishBase64Converter();

    try {
      if (base64ConverterType_ == Base64ConverterType.ANDROID)
        // Base64.DEFAULT is 0.
        return (byte[])base64Converter_.getDeclaredMethod
          ("decode", String.class, int.class).invoke(null, encoding, 0);
      else
        // Default to Base64ConverterType.JAVAX.
        return (byte[])base64Converter_.getDeclaredMethod
          ("parseBase64Binary", String.class).invoke(null, encoding);
    } catch (Exception ex) {
      throw new SecurityException("base64Decode: Error invoking method: " + ex);
    }
  }

  private final File keyStorePath_;
  private static Base64ConverterType base64ConverterType_ = Base64ConverterType.UNINITIALIZED;
  private static Class base64Converter_ = null;
}
