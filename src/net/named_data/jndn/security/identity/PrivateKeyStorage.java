/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security.identity;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;

public abstract class PrivateKeyStorage {
  /**
   * Generate a pair of asymmetric keys.
   * @param keyName The name of the key pair.
   * @param keyType The type of the key pair, e.g. KEY_TYPE_RSA.
   * @param keySize The size of the key pair.
   * @throws SecurityException
   */
  public abstract void 
  generateKeyPair
    (Name keyName, KeyType keyType, int keySize) throws SecurityException;

  /**
   * Generate a pair of asymmetric keys with key size 2048.
   * @param keyName The name of the key pair.
   * @param keyType The type of the key pair, e.g. KEY_TYPE_RSA.
   * @throws SecurityException
   */
  public final void 
  generateKeyPair(Name keyName, KeyType keyType) throws SecurityException
  {
    generateKeyPair(keyName, keyType, 2048);
  }

  /**
   * Generate a pair of RSA asymmetric keys with key size 2048.
   * @param keyName The name of the key pair.
   * @throws SecurityException
   */
  public final void 
  generateKeyPair(Name keyName) throws SecurityException
  {
    generateKeyPair(keyName, KeyType.RSA, 2048);
  }

  /**
   * Get the public key
   * @param keyName The name of public key.
   * @return The public key.
   * @throws SecurityException
   */
  public abstract PublicKey
  getPublicKey(Name keyName) throws SecurityException;
  
  /**
   * Fetch the private key for keyName and sign the data, returning a signature 
   * Blob.
   * @param data Pointer the input byte buffer to sign.
   * @param keyName The name of the signing key.
   * @param digestAlgorithm the digest algorithm.
   * @return The signature, or a null pointer if signing fails.
   * @throws SecurityException
   */  
  public abstract Blob 
  sign(ByteBuffer data, Name keyName, DigestAlgorithm digestAlgorithm)
      throws SecurityException;

  /**
   * Fetch the private key for keyName and sign the data using 
   * DigestAlgorithm.SHA256, returning a signature Blob.
   * @param data Pointer the input byte buffer to sign.
   * @param keyName The name of the signing key.
   * @return The signature, or a null pointer if signing fails.
   * @throws SecurityException
   */  
  public final Blob 
  sign(ByteBuffer data, Name keyName) throws SecurityException
  {
    return sign(data, keyName, DigestAlgorithm.SHA256);
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
  public abstract Blob 
  decrypt(Name keyName, ByteBuffer data, boolean isSymmetric) 
         throws SecurityException;

  /**
   * Decrypt data using asymmetric encryption.
   * @param keyName The name of the decrypting key.
   * @param data The byte buffer to be decrypted, from its position to its 
   * limit.
   * @return The decrypted data.
   * @throws SecurityException
   */
  public final Blob 
  decrypt(Name keyName, ByteBuffer data) throws SecurityException
  {
    return decrypt(keyName, data, false);
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
  public abstract Blob
  encrypt(Name keyName, ByteBuffer data, boolean isSymmetric) 
          throws SecurityException;

  /**
   * Encrypt data using asymmetric encryption.
   * @param keyName The name of the encrypting key.
   * @param data The byte buffer to be encrypted, from its position to its 
   * limit.
   * @return The encrypted data.
   * @throws SecurityException
   */
  public final Blob
  encrypt(Name keyName, ByteBuffer data) throws SecurityException
  {
    return encrypt(keyName, data, false);
  }

  /**
   * Generate a symmetric key.
   * @param keyName The name of the key.
   * @param keyType The type of the key, e.g. KeyType.AES.
   * @param keySize The size of the key.
   * @throws SecurityException
   */
  public abstract void 
  generateKey(Name keyName, KeyType keyType, int keySize) 
             throws SecurityException;

  /**
   * Generate a symmetric key of size 256.
   * @param keyName The name of the key.
   * @param keyType The type of the key, e.g. KeyType.AES.
   * @throws SecurityException
   */
  public final void 
  generateKey(Name keyName, KeyType keyType) throws SecurityException
  {
    generateKey(keyName, keyType, 256);
  }

  /**
   * Generate an AES symmetric key of size 256.
   * @param keyName The name of the key.
   * @throws SecurityException
   */
  public final void 
  generateKey(Name keyName) throws SecurityException
  {
    generateKey(keyName, KeyType.AES, 256);
  }
  
  /**
   * Check if a particular key exists.
   * @param keyName The name of the key.
   * @param keyClass The class of the key, e.g. KEY_CLASS_PUBLIC, 
   * KEY_CLASS_PRIVATE, or KEY_CLASS_SYMMETRIC.
   * @return True if the key exists, otherwise false.
   */
  public abstract boolean
  doesKeyExist(Name keyName, KeyClass keyClass);  
}
