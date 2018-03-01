/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.EcKeyParams;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.RsaKeyParams;
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
   * Create a new FilePrivateKeyStorage to connect to the default directory in
   * System.getProperty("user.home").
   */
  public FilePrivateKeyStorage()
  {
    keyStorePath_ = new File
      (getDefaultDirecoryPath(Common.getHomeDirectory()));
    keyStorePath_.mkdirs();
  }

  /**
   * Create a new FilePrivateKeyStorage to connect to the given directory.
   * @param keyStoreDirectoryPath The full path of the directory holding the
   * private key data. This creates the directory if it doesn't exist.
   * For example, you can get the default directory path from an Android files
   * directory with getDefaultDirecoryPath(context.getFilesDir())
   */
  public FilePrivateKeyStorage(String keyStoreDirectoryPath)
  {
    keyStorePath_ = new File(keyStoreDirectoryPath);
    keyStorePath_.mkdirs();
  }

  /**
   * Get the default directory path for private keys based on the files root.
   * For example if filesRoot is "/data/data/org.example/files", this returns
   * "/data/data/org.example/files/.ndn/ndnsec-tpm-file".
   * @param filesRoot The root file directory. An Android app can use
   * context.getFilesDir()
   * @return The default directory path.
   */
  public static String
  getDefaultDirecoryPath(File filesRoot)
  {
    return getDefaultDirecoryPath(filesRoot.getAbsolutePath());
  }

  /**
   * Get the default directory path for private keys based on the files root.
   * @param filesRoot The root file directory.
   * @return The default directory path.
   */
  public static String
  getDefaultDirecoryPath(String filesRoot)
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    return new File(new File(new File(filesRoot), ".ndn"), "ndnsec-tpm-file").getAbsolutePath();
  }

  /**
   * Generate a pair of asymmetric keys.
   * @param keyName The name of the key pair.
   * @param params The parameters of the key.
   * @throws SecurityException
   */
  public final void
  generateKeyPair(Name keyName, KeyParams params) throws SecurityException
  {
    if (doesKeyExist(keyName, KeyClass.PUBLIC))
      throw new SecurityException("Public Key already exists");
    if (doesKeyExist(keyName, KeyClass.PRIVATE))
      throw new SecurityException("Private Key already exists");

    String keyAlgorithm;
    int keySize;
    if (params.getKeyType() == KeyType.RSA) {
      keyAlgorithm = "RSA";
      keySize = ((RsaKeyParams)params).getKeySize();
    }
    else if (params.getKeyType() == KeyType.EC) {
      keyAlgorithm = "EC";
      keySize = ((EcKeyParams)params).getKeySize();
    }
    else
      throw new SecurityException("Cannot generate a key pair of type " + params.getKeyType());

    KeyPairGenerator generator = null;
    try{
      generator = KeyPairGenerator.getInstance(keyAlgorithm);
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
   * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
   * @param keyName The name of the key pair.
   */
  public void
  deleteKeyPair(Name keyName) throws SecurityException
  {
    try {
      // deleteKeyPair is required by an older API which will be changed.
      // For now, call deleteKey.
      deleteKey(keyName);
    } catch (SecurityException ex) {
      // In the deleteKeyPair API, do nothing if the key doesn't exist.
    }
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

    return new PublicKey(new Blob(der, false));
  }

  /**
   * Get the private key for this name; internal helper method
   * @param keyName The name of the key.
   * @param keyType Set keyType[0] to the KeyType.
   * @return The java.security.PrivateKey.
   * @throws SecurityException
   */
  private PrivateKey
  getPrivateKey(Name keyName, KeyType[] keyType) throws SecurityException
  {
    if (!doesKeyExist(keyName, KeyClass.PRIVATE))
      throw new SecurityException
        ("FilePrivateKeyStorage: Private key does not exist.");

    // Read the file contents.
    byte[] der = this.read(keyName, KeyClass.PRIVATE);

    // Decode the PKCS #8 DER to find the algorithm OID.
    String oidString = null;
    try {
      DerNode parsedNode = DerNode.parse(ByteBuffer.wrap(der), 0);
      List pkcs8Children = parsedNode.getChildren();
      List algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren();
      oidString = "" + ((DerNode.DerOid)algorithmIdChildren.get(0)).toVal();
    }
    catch (DerDecodingException ex) {
      throw new SecurityException("Cannot decode the PKCS #8 private key: " + ex);
    }

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    if (oidString.equals(RSA_ENCRYPTION_OID)) {
      keyType[0] = KeyType.RSA;

      try {
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
    else if (oidString.equals(EC_ENCRYPTION_OID)) {
      keyType[0] = KeyType.EC;

      try {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
      }
      catch(InvalidKeySpecException e){
        // Don't expect this to happen.
        throw new SecurityException
          ("FilePrivateKeyStorage: EC is not supported: " + e.getMessage());
      }
      catch(NoSuchAlgorithmException e){
        // Don't expect this to happen.
        throw new SecurityException
          ("FilePrivateKeyStorage: PKCS8EncodedKeySpec is not supported for EC: "
                  + e.getMessage());
      }
    }
    else
      throw new SecurityException
        ("FilePrivateKeyStorage.sign: Unrecognized private key OID: " + oidString);
  }

  /**
   * Get the symmetric key for this name; internal helper method
   * @param keyName
   * @return The symmetric key.
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
   * @return The signature Blob.
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
    KeyType[] keyType = new KeyType[1];
    PrivateKey privateKey = getPrivateKey(keyName, keyType);

    // Sign.
    java.security.Signature signature = null;
    if (keyType[0] == KeyType.RSA) {
      try {
        signature = java.security.Signature.getInstance("SHA256withRSA");
      }
      catch (NoSuchAlgorithmException e) {
        // Don't expect this to happen.
        throw new SecurityException
          ("FilePrivateKeyStorage: The SHA256withRSA algorithm is not supported");
      }
    }
    else if (keyType[0] == KeyType.EC) {
      try {
        signature = java.security.Signature.getInstance("SHA256withECDSA");
      }
      catch (NoSuchAlgorithmException e) {
        // Don't expect this to happen.
        throw new SecurityException
          ("FilePrivateKeyStorage: The SHA256withECDSA algorithm is not supported");
      }
    }
    else
      // We don't expect this to happen since getPrivateKey checked it.
      throw new SecurityException
        ("FilePrivateKeyStorage: Unsupported signature key type " + keyType[0]);

    try {
      signature.initSign(privateKey);
    }
    catch (InvalidKeyException exception) {
      throw new SecurityException
        ("FilePrivateKeyStorage: InvalidKeyException: " + exception.getMessage());
    }
    try {
      signature.update(data);
      return new Blob(signature.sign(), false);
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
    throw new UnsupportedOperationException
      ("FilePrivateKeyStorage.decrypt is not implemented");
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
    throw new UnsupportedOperationException
      ("FilePrivateKeyStorage.encrypt is not implemented");
  }

  /**
   * Generate a symmetric key.
   * @param keyName The name of the key.
   * @param params The parameters of the key.
   * @throws SecurityException
   */
  public final void
  generateKey(Name keyName, KeyParams params) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("FilePrivateKeyStorage.generateKey is not implemented");
  }

  /**
   * Delete a key by name; checks all KeyClass types
   * @param keyName
   * @throws SecurityException
   */
  public final void
  deleteKey(Name keyName) throws SecurityException
  {
    int deletedFiles = 0;
    for(KeyClass keyClass : KeyClass.values()){
      if (doesKeyExist(keyName, keyClass)){
        String extension = (String) keyTypeMap_.get(keyClass);
        File file = nameTransform(keyName.toUri(), extension);
        file.delete();
        deletedFiles++;
      }
    }
    if(deletedFiles == 0){
      throw new SecurityException("No key files found to delete");
    }
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
   * @return The hashed file path.
   * @throws SecurityException
   */
  private File
  nameTransform(String keyName, String extension) throws SecurityException
  {
    byte[] hash;
    try {
      hash = Common.digestSha256(keyName.getBytes("UTF-8"));
    } catch (UnsupportedEncodingException ex) {
      // We don't expect this to happen.
      throw new Error("UTF-8 encoder not supported: " + ex.getMessage());
    }
    String digest = Common.base64Encode(hash);
    digest = digest.replace('/', '%');

    return new File(keyStorePath_, digest + extension);
  }

  /**
   * Use nameTransform to get the file path for keyName (without the extension)
   * and also add to the mapping.txt file.
   * @param keyName The key name which is transformed to a file path.
   * @return The key file path without the extension.
   */
  private String
  maintainMapping(String keyName) throws SecurityException
  {
    String keyFilePathNoExtension = nameTransform(keyName, "").getAbsolutePath();

    File mappingFilePath = new File(keyStorePath_, "mapping.txt");

    try{
      BufferedWriter writer = new BufferedWriter
        (new FileWriter(mappingFilePath.getAbsolutePath(), true));
      try {
        writer.write(keyName + ' ' + keyFilePathNoExtension + '\n');
        writer.flush();
      }
      finally{
        writer.close();
      }
    }
    catch(IOException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to write to mapping.txt: " + e.getMessage());
    }

    return keyFilePathNoExtension;
  }

  /**
   * Write to a key file. If keyClass is PRIVATE, then also update mapping.txt.
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
      String filePath;
      if (keyClass == KeyClass.PRIVATE)
        filePath = maintainMapping(keyName.toUri()) + extension;
      else
        filePath = nameTransform(keyName.toUri(), extension).getAbsolutePath();

      BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
      try{
        String base64Data = Common.base64Encode(data, true);
        writer.write(base64Data, 0, base64Data.length());
        writer.flush();
      }
      finally{
        writer.close();
      }
    }
    catch(SecurityException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to write key: " + e.getMessage());
    }
    catch(IOException e){
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to write key: " + e.getMessage());
    }
  }

  /**
   * Read from a key file
   * @param keyName
   * @param keyClass [PUBLIC, PRIVATE, SYMMETRIC]
   * @return The key bytes.
   * @throws IOException
   * @throws SecurityException
   */
  private byte[]
  read(Name keyName, KeyClass keyClass) throws SecurityException{
    String extension = (String) keyTypeMap_.get(keyClass);
    StringBuilder contents = new StringBuilder();
    try{
      BufferedReader reader = new BufferedReader
        (new FileReader(nameTransform(keyName.toUri(), extension).getAbsolutePath()));
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
    catch(SecurityException e) {
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to read key: " + e.getMessage());
    }
    catch(IOException e) {
      throw new SecurityException
        ("FilePrivateKeyStorage: Failed to read key: " + e.getMessage());
    }

    return Common.base64Decode(contents.toString());
  }

  static private String RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
  static private String EC_ENCRYPTION_OID = "1.2.840.10045.2.1";

  private final File keyStorePath_;
  // Use HashMap without generics so it works with older Java compilers.
  private static final HashMap keyTypeMap_;
  static{
    keyTypeMap_ = new HashMap();
    keyTypeMap_.put(KeyClass.PUBLIC, ".pub");
    keyTypeMap_.put(KeyClass.PRIVATE, ".pri");
    keyTypeMap_.put(KeyClass.SYMMETRIC, ".key");
  }
}
