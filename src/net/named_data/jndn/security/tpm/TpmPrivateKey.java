/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From https://github.com/named-data/ndn-cxx/blob/master/src/security/transform/private-key.cpp
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

package net.named_data.jndn.security.tpm;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.encoding.OID;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.encoding.der.DerNode.DerSequence;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.EcKeyParams;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * A TpmPrivateKey holds an in-memory private key and provides cryptographic
 * operations such as for signing by the in-memory TPM.
 */
public class TpmPrivateKey {
  /**
   * A TpmPrivateKey.Error extends Exception and represents an error in private
   * key processing.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Create an uninitialized TpmPrivateKey. You must call a load method to
   * initialize it, such as loadPkcs1.
   */
  public TpmPrivateKey() {}

  /**
   * Load the unencrypted private key from a buffer with the PKCS #1 encoding.
   * This replaces any existing private key in this object.
   * @param encoding The byte buffer with the private key encoding.
   * @param keyType The KeyType, such as KeyType.RSA. If null, then partially
   * decode the private key to determine the key type.
   * @throws TpmPrivateKey.Error for errors decoding the key.
   */
  public final void
  loadPkcs1(ByteBuffer encoding, KeyType keyType) throws TpmPrivateKey.Error
  {
    if (keyType == null) {
      // Try to determine the key type.
      try {
        DerNode parsedNode = DerNode.parse(encoding);
        List children = parsedNode.getChildren();

        // An RsaPrivateKey has integer version 0 and 8 integers.
        if (children.size() == 9 &&
            children.get(0) instanceof DerNode.DerInteger &&
            ((int)((DerNode.DerInteger)children.get(0)).toVal()) == 0 &&
            children.get(1) instanceof DerNode.DerInteger &&
            children.get(2) instanceof DerNode.DerInteger &&
            children.get(3) instanceof DerNode.DerInteger &&
            children.get(4) instanceof DerNode.DerInteger &&
            children.get(5) instanceof DerNode.DerInteger &&
            children.get(6) instanceof DerNode.DerInteger &&
            children.get(7) instanceof DerNode.DerInteger &&
            children.get(8) instanceof DerNode.DerInteger)
          keyType = KeyType.RSA;
        else
          // Assume it is an EC key. Try decoding it below.
          keyType = KeyType.EC;
      } catch (DerDecodingException ex) {
        // Assume it is an EC key. Try decoding it below.
        keyType = KeyType.EC;
      }
    }

    // Java can't decode a PKCS #1 private key, so make a PKCS #8 private key
    // and decode that.
    Blob pkcs8;
    if (keyType == KeyType.EC) {
      throw new TpmPrivateKey.Error("TODO: loadPkcs1 for EC is not implemented");
    }
    else if (keyType == KeyType.RSA)
      pkcs8 = encodePkcs8PrivateKey
        (encoding, new OID(RSA_ENCRYPTION_OID), new DerNode.DerNull());
    else
      throw new TpmPrivateKey.Error("loadPkcs1: Unrecognized keyType: " + keyType);

    loadPkcs8(pkcs8.buf(), keyType);
  }

  /**
   * Load the unencrypted private key from a buffer with the PKCS #1 encoding.
   * This replaces any existing private key in this object. This partially
   * decodes the private key to determine the key type.
   * @param encoding The byte buffer with the private key encoding.
   * @throws TpmPrivateKey.Error for errors decoding the key.
   */
  public final void
  loadPkcs1(ByteBuffer encoding) throws TpmPrivateKey.Error
  {
    loadPkcs1(encoding, null);
  }

  /**
   * Load the unencrypted private key from a buffer with the PKCS #8 encoding.
   * This replaces any existing private key in this object.
   * @param encoding The byte buffer with the private key encoding.
   * @param keyType The KeyType, such as KeyType.RSA. If null, then partially
   * decode the private key to determine the key type.
   * @throws TpmPrivateKey.Error for errors decoding the key.
   */
  public final void
  loadPkcs8(ByteBuffer encoding, KeyType keyType) throws TpmPrivateKey.Error
  {
    if (keyType == null) {
      // Decode the PKCS #8 DER to find the algorithm OID.
      String oidString = null;
      try {
        DerNode parsedNode = DerNode.parse(encoding, 0);
        List pkcs8Children = parsedNode.getChildren();
        List algorithmIdChildren = DerNode.getSequence
          (pkcs8Children, 1).getChildren();
        oidString = "" + ((DerNode.DerOid)algorithmIdChildren.get(0)).toVal();
      }
      catch (DerDecodingException ex) {
        throw new TpmPrivateKey.Error
          ("Cannot decode the PKCS #8 private key: " + ex);
      }

      if (oidString.equals(EC_ENCRYPTION_OID))
        keyType = KeyType.EC;
      else if (oidString.equals(RSA_ENCRYPTION_OID))
        keyType = KeyType.RSA;
      else
        throw new TpmPrivateKey.Error
          ("loadPkcs8: Unrecognized private key OID: " + oidString);
    }

    // Use a Blob to get the byte array.
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec
      (new Blob(encoding, false).getImmutableArray());
    if (keyType == KeyType.EC) {
      try {
        KeyFactory kf = KeyFactory.getInstance("EC");
        privateKey_ = kf.generatePrivate(spec);
        keyType_ = KeyType.EC;
      }
      catch (InvalidKeySpecException ex) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error("loadPkcs8: EC is not supported: " + ex);
      }
      catch (NoSuchAlgorithmException ex) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error
          ("loadPkcs8: PKCS8EncodedKeySpec is not supported for EC: " + ex);
      }
    }
    else if (keyType == KeyType.RSA) {
      try {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey_ = kf.generatePrivate(spec);
        keyType_ = KeyType.RSA;
      }
      catch (InvalidKeySpecException ex) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error("loadPkcs8: RSA is not supported: " + ex);
      }
      catch (NoSuchAlgorithmException ex) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error
          ("loadPkcs8: PKCS8EncodedKeySpec is not supported for RSA: " + ex);
      }
    }
    else
      throw new TpmPrivateKey.Error
        ("loadPkcs8: Unrecognized keyType: " + keyType);
  }

  /**
   * Load the unencrypted private key from a buffer with the PKCS #8 encoding.
   * This replaces any existing private key in this object. This partially
   * decodes the private key to determine the key type.
   * @param encoding The byte buffer with the private key encoding.
   * @throws TpmPrivateKey.Error for errors decoding the key.
   */
  public final void
  loadPkcs8(ByteBuffer encoding) throws TpmPrivateKey.Error
  {
    loadPkcs8(encoding, null);
  }

  /**
   * Load the encrypted private key from a buffer with the PKCS #8 encoding of
   * the EncryptedPrivateKeyInfo.
   * This replaces any existing private key in this object. This partially
   * decodes the private key to determine the key type.
   * @param encoding The byte buffer with the private key encoding.
   * @param password The password for decrypting the private key, which should
   * have characters in the range of 1 to 127.
   * @throws TpmPrivateKey.Error for errors decoding or decrypting the key.
   */
  public final void
  loadEncryptedPkcs8(ByteBuffer encoding, ByteBuffer password)
    throws TpmPrivateKey.Error
  {
    // Decode the PKCS #8 EncryptedPrivateKeyInfo.
    // See https://tools.ietf.org/html/rfc5208.
    String oidString;
    Object parameters;
    Blob encryptedKey;
    try {
      DerNode parsedNode = DerNode.parse(encoding, 0);
      List encryptedPkcs8Children = parsedNode.getChildren();
      List algorithmIdChildren = DerNode.getSequence
        (encryptedPkcs8Children, 0).getChildren();
      oidString = "" + ((DerNode.DerOid)algorithmIdChildren.get(0)).toVal();
      parameters = algorithmIdChildren.get(1);

      encryptedKey = 
        (Blob)((DerNode.DerOctetString)encryptedPkcs8Children.get(1)).toVal();
    }
    catch (Throwable ex) {
      throw new TpmPrivateKey.Error
        ("Cannot decode the PKCS #8 EncryptedPrivateKeyInfo: " + ex);
    }

    // Use the password to get the unencrypted pkcs8Encoding.
    byte[] pkcs8Encoding;
    if (oidString.equals(PBES2_OID)) {
      // Decode the PBES2 parameters. See https://www.ietf.org/rfc/rfc2898.txt .
      String keyDerivationOidString;
      Object keyDerivationParameters;
      String encryptionSchemeOidString;
      Object encryptionSchemeParameters;
      try {
        List parametersChildren = ((DerNode.DerSequence)parameters).getChildren();

        List keyDerivationAlgorithmIdChildren = DerNode.getSequence
          (parametersChildren, 0).getChildren();
        keyDerivationOidString = "" +
          ((DerNode.DerOid)keyDerivationAlgorithmIdChildren.get(0)).toVal();
        keyDerivationParameters = keyDerivationAlgorithmIdChildren.get(1);

        List encryptionSchemeAlgorithmIdChildren = DerNode.getSequence
          (parametersChildren, 1).getChildren();
        encryptionSchemeOidString = "" +
          ((DerNode.DerOid)encryptionSchemeAlgorithmIdChildren.get(0)).toVal();
        encryptionSchemeParameters = encryptionSchemeAlgorithmIdChildren.get(1);
      }
      catch (Throwable ex) {
        throw new TpmPrivateKey.Error
          ("Cannot decode the PBES2 parameters: " + ex);
      }

      // Get the derived key from the password.
      byte[] derivedKey = null;
      if (keyDerivationOidString.equals(PBKDF2_OID)) {
        // Decode the PBKDF2 parameters.
        Blob salt;
        int nIterations;
        try {
          List pbkdf2ParametersChildren =
            ((DerNode.DerSequence)keyDerivationParameters).getChildren();
          salt = (Blob)
            ((DerNode.DerOctetString)pbkdf2ParametersChildren.get(0)).toVal();
          nIterations = (int)
            ((DerNode.DerInteger)pbkdf2ParametersChildren.get(1)).toVal();
        }
        catch (Throwable ex) {
          throw new TpmPrivateKey.Error
            ("Cannot decode the PBES2 parameters: " + ex);
        }

        // Check the encryption scheme here to get the needed result length.
        int resultLength;
        if (encryptionSchemeOidString.equals(DES_EDE3_CBC_OID))
          resultLength = DES_EDE3_KEY_LENGTH;
        else
          throw new TpmPrivateKey.Error
            ("Unrecognized PBES2 encryption scheme OID: " +
             encryptionSchemeOidString);

        try {
          derivedKey = Common.computePbkdf2WithHmacSha1
            (new Blob(password, false).getImmutableArray(),
             salt.getImmutableArray(), nIterations, resultLength);
        }
        catch (Throwable ex) {
          throw new TpmPrivateKey.Error
            ("Error computing the derived key using PBKDF2 with HMAC SHA1: " + ex);
        }
      }
      else
        throw new TpmPrivateKey.Error
          ("Unrecognized PBES2 key derivation OID: " + keyDerivationOidString);

      // Use the derived key to get the unencrypted pkcs8Encoding.
      if (encryptionSchemeOidString.equals(DES_EDE3_CBC_OID)) {
        // Decode the DES-EDE3-CBC parameters.
        Blob initialVector;
        try {
          initialVector = (Blob)
            ((DerNode.DerOctetString)encryptionSchemeParameters).toVal();
        }
        catch (Throwable ex) {
          throw new TpmPrivateKey.Error
            ("Cannot decode the DES-EDE3-CBC parameters: " + ex);
        }

        try {
          Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
          cipher.init
            (Cipher.DECRYPT_MODE,
             new SecretKeySpec(derivedKey, "DESede"),
             new IvParameterSpec(initialVector.getImmutableArray()));
          pkcs8Encoding = cipher.doFinal(encryptedKey.getImmutableArray());
        }
        catch (Throwable ex) {
          throw new TpmPrivateKey.Error
            ("Error decrypting PKCS #8 key with DES-EDE3-CBC: " + ex);
        }
      }
      else
        throw new TpmPrivateKey.Error
          ("Unrecognized PBES2 encryption scheme OID: " +
           encryptionSchemeOidString);
    }
    else
      throw new TpmPrivateKey.Error
        ("Unrecognized PKCS #8 EncryptedPrivateKeyInfo OID: " + oidString);

    loadPkcs8(ByteBuffer.wrap(pkcs8Encoding));
  }

  /**
   * Get the encoded public key for this private key.
   * @return The public key encoding Blob.
   * @throws TpmPrivateKey.Error if no private key is loaded, or error
   * converting to a public key.
   */
  public final Blob
  derivePublicKey() throws TpmPrivateKey.Error
  {
    if (keyType_ == KeyType.EC) {
      throw new TpmPrivateKey.Error
        ("TODO: derivePublicKey for EC is not implemented");
    }
    else if (keyType_ == KeyType.RSA) {
      // Decode the PKCS #1 RSAPrivateKey. (We don't use RSAPrivateCrtKey because
      // the Android library doesn't have an easy way to decode into it.)
      List rsaPrivateKeyChildren;
      try {
        DerNode parsedNode = DerNode.parse(toPkcs1().buf(), 0);
        rsaPrivateKeyChildren = parsedNode.getChildren();
      } catch (DerDecodingException ex) {
        throw new TpmPrivateKey.Error
          ("Error parsing RSA PKCS #1 key: " + ex);
      }
      Blob modulus = ((DerNode)rsaPrivateKeyChildren.get(1)).getPayload();
      Blob publicExponent = ((DerNode)rsaPrivateKeyChildren.get(2)).getPayload();

      try {
        java.security.PublicKey publicKey =
          KeyFactory.getInstance("RSA").generatePublic
            (new RSAPublicKeySpec
             (new BigInteger(modulus.getImmutableArray()),
              new BigInteger(publicExponent.getImmutableArray())));
        return new Blob(publicKey.getEncoded(), false);
      } catch (Exception ex) {
        throw new TpmPrivateKey.Error("Error making RSA public key: " + ex);
      }
    }
    else
      throw new TpmPrivateKey.Error
        ("derivePublicKey: The private key is not loaded");
  }

  /**
   * Decrypt the cipherText using this private key according the encryption
   * algorithmType. Only RSA encryption is supported for now.
   * @param cipherText The cipher text byte buffer.
   * @param algorithmType This decrypts according to algorithmType.
   * @return The decrypted data.
   * @throws TpmPrivateKey.Error if the private key is not loaded, if
   * decryption is not supported for this key type, or for error decrypting.
   */
  public final Blob
  decrypt(ByteBuffer cipherText, EncryptAlgorithmType algorithmType)
    throws TpmPrivateKey.Error
  {
    if (keyType_ == null)
      throw new TpmPrivateKey.Error("decrypt: The private key is not loaded");

    String transformation;
    if (algorithmType == EncryptAlgorithmType.RsaPkcs)
      transformation = "RSA/ECB/PKCS1Padding";
    else if (algorithmType == EncryptAlgorithmType.RsaOaep)
      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    else
      throw new TpmPrivateKey.Error("unsupported padding scheme");

    try {
      Cipher cipher = Cipher.getInstance(transformation);
      cipher.init(Cipher.DECRYPT_MODE, privateKey_);
      // Use Blob to get the byte array.
      byte[] cipherByteArray = new Blob(cipherText, false).getImmutableArray();
      return new Blob(cipher.doFinal(cipherByteArray), false);
    } catch (Exception ex) {
      throw new TpmPrivateKey.Error
        ("Error decrypting with private key: " + ex.getMessage());
    }
  }

  /**
   * Call the main decrypt where algorithmType is RsaOaep.
   */
  public final Blob
  decrypt(ByteBuffer cipherText) throws TpmPrivateKey.Error
  {
    return decrypt(cipherText, EncryptAlgorithmType.RsaOaep);
  }

  /**
   * Sign the data with this private key, returning a signature Blob.
   * @param data The input byte buffer.
   * @param digestAlgorithm the digest algorithm.
   * @return The signature Blob, or an isNull Blob if this private key is not
   * initialized.
   * @throws TpmPrivateKey.Error for unrecognized digestAlgorithm or an error
   * in signing.
   */
  public final Blob
  sign(ByteBuffer data, DigestAlgorithm digestAlgorithm)
    throws TpmPrivateKey.Error
  {
    if (digestAlgorithm != DigestAlgorithm.SHA256)
      throw new TpmPrivateKey.Error
        ("TpmPrivateKey.sign: Unsupported digest algorithm");

    java.security.Signature signature = null;
    if (keyType_ == KeyType.EC) {
      try {
        signature = java.security.Signature.getInstance("SHA256withECDSA");
      }
      catch (NoSuchAlgorithmException e) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error
          ("SHA256withECDSA algorithm is not supported");
      }
    }
    else if (keyType_ == KeyType.RSA) {
      try {
        signature = java.security.Signature.getInstance("SHA256withRSA");
      }
      catch (NoSuchAlgorithmException e) {
        // Don't expect this to happen.
        throw new TpmPrivateKey.Error("SHA256withRSA algorithm is not supported");
      }
    }
    else
      return new Blob();

    try {
      signature.initSign(privateKey_);
    }
    catch (InvalidKeyException exception) {
      throw new TpmPrivateKey.Error
        ("InvalidKeyException: " + exception.getMessage());
    }
    try {
      signature.update(data);
      return new Blob(signature.sign(), false);
    }
    catch (SignatureException exception) {
      throw new TpmPrivateKey.Error
        ("SignatureException: " + exception.getMessage());
    }
  }

  /**
   * Get the encoded unencrypted private key in PKCS #1.
   * @return The private key encoding Blob.
   * @throws TpmPrivateKey.Error if no private key is loaded, or error encoding.
   */
  public final Blob
  toPkcs1() throws TpmPrivateKey.Error
  {
    if (keyType_ == null)
      throw new TpmPrivateKey.Error("toPkcs1: The private key is not loaded");

    // Decode the PKCS #8 private key.
    DerNode parsedNode;
    try {
      parsedNode = DerNode.parse(toPkcs8().buf(), 0);
      List pkcs8Children = parsedNode.getChildren();
      return ((DerNode)pkcs8Children.get(2)).getPayload();
    } catch (DerDecodingException ex) {
      throw new TpmPrivateKey.Error("Error decoding PKCS #8 private key: " + ex);
    }
  }

  /**
   * Get the encoded unencrypted private key in PKCS #8.
   * @return The private key encoding Blob.
   * @throws TpmPrivateKey.Error if no private key is loaded, or error encoding.
   */
  public final Blob
  toPkcs8() throws TpmPrivateKey.Error
  {
    if (keyType_ == null)
      throw new TpmPrivateKey.Error("toPkcs8: The private key is not loaded");

    return new Blob(privateKey_.getEncoded());
  }

  /**
   * Get the encoded encrypted private key in PKCS #8.
   * @param password The password for encrypting the private key, which should
   * have characters in the range of 1 to 127.
   * @return The encoding Blob of the EncryptedPrivateKeyInfo.
   * @throws TpmPrivateKey.Error if no private key is loaded, or error encoding.
   */
  public final Blob
  toEncryptedPkcs8(ByteBuffer password) throws TpmPrivateKey.Error
  {
    if (keyType_ == null)
      throw new TpmPrivateKey.Error
        ("toEncryptedPkcs8: The private key is not loaded");

    // Create the derivedKey from the password.
    final int nIterations = 2048;
    byte[] salt = new byte[8];
    Common.getRandom().nextBytes(salt);
    byte[] derivedKey;
    try {
      derivedKey = Common.computePbkdf2WithHmacSha1
        (new Blob(password, false).getImmutableArray(),
         salt, nIterations, DES_EDE3_KEY_LENGTH);
    }
    catch (Throwable ex) {
      // We don't expect this to happen.
      throw new TpmPrivateKey.Error
        ("Error computing the derived key using PBKDF2 with HMAC SHA1: " + ex);
    }

    // Use the derived key to get the encrypted pkcs8Encoding.
    byte[] encryptedEncoding;
    byte[] initialVector = new byte[8];
    Common.getRandom().nextBytes(initialVector);
    try {
      Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      cipher.init
        (Cipher.ENCRYPT_MODE,
         new SecretKeySpec(derivedKey, "DESede"),
         new IvParameterSpec(initialVector));
      encryptedEncoding = cipher.doFinal(privateKey_.getEncoded());
    }
    catch (Throwable ex) {
      throw new TpmPrivateKey.Error
        ("Error encrypting PKCS #8 key with DES-EDE3-CBC: " + ex);
    }

    try {
      // Encode the PBES2 parameters. See https://www.ietf.org/rfc/rfc2898.txt .
      DerSequence keyDerivationParameters = new DerSequence();
      keyDerivationParameters.addChild(new DerNode.DerOctetString
        (ByteBuffer.wrap(salt)));
      keyDerivationParameters.addChild(new DerNode.DerInteger(nIterations));
      DerSequence keyDerivationAlgorithmIdentifier = new DerSequence();
      keyDerivationAlgorithmIdentifier.addChild(new DerNode.DerOid
        (PBKDF2_OID));
      keyDerivationAlgorithmIdentifier.addChild(keyDerivationParameters);

      DerSequence encryptionSchemeAlgorithmIdentifier = new DerSequence();
      encryptionSchemeAlgorithmIdentifier.addChild(new DerNode.DerOid
        (DES_EDE3_CBC_OID));
      encryptionSchemeAlgorithmIdentifier.addChild(new DerNode.DerOctetString
        (ByteBuffer.wrap(initialVector)));

      DerSequence encryptedKeyParameters = new DerSequence();
      encryptedKeyParameters.addChild(keyDerivationAlgorithmIdentifier);
      encryptedKeyParameters.addChild(encryptionSchemeAlgorithmIdentifier);
      DerSequence encryptedKeyAlgorithmIdentifier = new DerSequence();
      encryptedKeyAlgorithmIdentifier.addChild(new DerNode.DerOid(PBES2_OID));
      encryptedKeyAlgorithmIdentifier.addChild(encryptedKeyParameters);

      // Encode the PKCS #8 EncryptedPrivateKeyInfo.
      // See https://tools.ietf.org/html/rfc5208.
      DerSequence encryptedKey = new DerSequence();
      encryptedKey.addChild(encryptedKeyAlgorithmIdentifier);
      encryptedKey.addChild(new DerNode.DerOctetString
        (ByteBuffer.wrap(encryptedEncoding)));

      return encryptedKey.encode();
    } catch (DerEncodingException ex) {
      throw new TpmPrivateKey.Error
        ("Error encoding the encryped PKCS #8 private key: " + ex);
    }
  }

  /**
   * Generate a key pair according to keyParams and return a new TpmPrivateKey
   * with the private key. You can get the public key with derivePublicKey.
   * @param keyParams The parameters of the key.
   * @return A new TpmPrivateKey.
   * @throws IllegalArgumentException if the key type is not supported.
   * @throws TpmPrivateKey.Error for an invalid key size, or an error generating.
   */
  public static TpmPrivateKey
  generatePrivateKey(KeyParams keyParams)
    throws IllegalArgumentException, TpmPrivateKey.Error
  {
    String keyAlgorithm;
    int keySize;
    if (keyParams.getKeyType() == KeyType.RSA) {
      keyAlgorithm = "RSA";
      keySize = ((RsaKeyParams)keyParams).getKeySize();
    }
    else if (keyParams.getKeyType() == KeyType.EC) {
      keyAlgorithm = "EC";
      keySize = ((EcKeyParams)keyParams).getKeySize();
    }
    else
      throw new IllegalArgumentException
        ("Cannot generate a key pair of type " + keyParams.getKeyType());

    KeyPairGenerator generator = null;
    try{
      generator = KeyPairGenerator.getInstance(keyAlgorithm);
    }
    catch(NoSuchAlgorithmException e){
      throw new TpmPrivateKey.Error
        ("TpmPrivateKey: Could not create the key generator: " + e.getMessage());
    }

    generator.initialize(keySize);
    KeyPair pair = generator.generateKeyPair();

    TpmPrivateKey result = new TpmPrivateKey();
    result.keyType_ = keyParams.getKeyType();
    result.privateKey_ = pair.getPrivate();

    return result;
  }

  /**
   * Encode the private key to a PKCS #8 private key. We do this explicitly here
   * to avoid linking to extra OpenSSL libraries.
   * @param privateKeyDer The input private key DER.
   * @param oid The OID of the privateKey.
   * @param parameters The DerNode of the parameters for the OID.
   * @return The PKCS #8 private key DER.
   */
  private static Blob
  encodePkcs8PrivateKey(ByteBuffer privateKeyDer, OID oid, DerNode parameters)
    throws TpmPrivateKey.Error
  {
    try {
      DerSequence algorithmIdentifier = new DerSequence();
      algorithmIdentifier.addChild(new DerNode.DerOid(oid));
      algorithmIdentifier.addChild(parameters);

      DerSequence result = new DerSequence();
      result.addChild(new DerNode.DerInteger(0));
      result.addChild(algorithmIdentifier);
      result.addChild(new DerNode.DerOctetString(privateKeyDer));

      return result.encode();
    } catch (DerEncodingException ex) {
      throw new TpmPrivateKey.Error("Error encoding PKCS #8 private key: " + ex);
    }
  }

  private static final String RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
  private static final String EC_ENCRYPTION_OID = "1.2.840.10045.2.1";
  private static final String PBES2_OID = "1.2.840.113549.1.5.13";
  private static final String PBKDF2_OID = "1.2.840.113549.1.5.12";
  private static final String DES_EDE3_CBC_OID = "1.2.840.113549.3.7";
  private static final int DES_EDE3_KEY_LENGTH = 24;

  private KeyType keyType_ = null;
  private java.security.PrivateKey privateKey_;
}
