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
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;
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
    keyStorePath_ = Paths.get
      (System.getProperty("user.home", "."), ".ndn", "ndnsec-tpm-file");
    keyStorePath_.toFile().mkdirs();
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
    throw new Error("FilePrivateKeyStorage::generateKeyPair not implemented");
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
        (new FileReader(nameTransform(keyURI, ".pub").toFile()));
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

    byte[] der = DatatypeConverter.parseBase64Binary(contents.toString());

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
        ("FilePrivateKeyStorage::sign: private key doesn't exist");

    if (digestAlgorithm != DigestAlgorithm.SHA256)
      throw new SecurityException
        ("FilePrivateKeyStorage::sign: Unsupported digest algorithm");

    // Read the private key.
    StringBuilder contents = new StringBuilder();
    try {
      BufferedReader reader = new BufferedReader
        (new FileReader(nameTransform(keyURI, ".pri").toFile()));
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

    byte[] der = DatatypeConverter.parseBase64Binary(contents.toString());

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
    throw new Error("FilePrivateKeyStorage::decrypt not implemented");
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
    throw new Error("FilePrivateKeyStorage::encrypt not implemented");
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
    throw new Error("FilePrivateKeyStorage::generateKey not implemented");
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
      return nameTransform(keyURI, ".pub").toFile().exists();
    else if (keyClass == KeyClass.PRIVATE)
      return nameTransform(keyURI, ".pri").toFile().exists();
    else if (keyClass == KeyClass.SYMMETRIC)
      return nameTransform(keyURI, ".key").toFile().exists();
    else
      return false;
  }

  private Path
  nameTransform(String keyName, String extension)
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

    String digest = DatatypeConverter.printBase64Binary(hash);
    digest = digest.replace('/', '%');

    return keyStorePath_.resolve(digest + extension);
  }

  private final Path keyStorePath_;
}
