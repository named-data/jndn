/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security.identity;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SignedBlob;

/**
 * An IdentityManager is the interface of operations related to identity, keys, 
 * and certificates.
 */
public class IdentityManager {
  /**
   * Create a new IdentityManager to use the given identity and private key 
   * storage.
   * @param identityStorage An object of a subclass of IdentityStorage.
   * @param privateKeyStorage An object of a subclass of PrivateKeyStorage.
   */
  public IdentityManager
    (IdentityStorage identityStorage, PrivateKeyStorage privateKeyStorage)
  {
    identityStorage_ = identityStorage;
    privateKeyStorage_ = privateKeyStorage;
  }
    
  /**
   * Create an identity by creating a pair of Key-Signing-Key (KSK) for this 
   * identity and a self-signed certificate of the KSK.
   * @param identityName The name of the identity.
   * @return The key name of the auto-generated KSK of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public Name
  createIdentity(Name identityName) throws SecurityException
  {
    if (!identityStorage_.doesIdentityExist(identityName)) {
      Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Create Identity");
      identityStorage_.addIdentity(identityName);

      Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Create Default RSA key pair");
      Name keyName = generateRSAKeyPairAsDefault(identityName, true);

      Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Create self-signed certificate");
      IdentityCertificate selfCert = selfSign(keyName); 

      Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Add self-signed certificate as default");

      addCertificateAsDefault(selfCert);

      return keyName;
    }
    else
      throw new SecurityException("Identity has already been created!");
  }
  
  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public Name
  getDefaultIdentity() throws SecurityException
  {
    return identityStorage_.getDefaultIdentity();
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keySize The size of the key.
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPair
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, KeyType.RSA, keySize);

    return keyName;
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity and default keySize
   * 2048.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPair(Name identityName, boolean isKsk) throws SecurityException
  {
    return generateRSAKeyPair(identityName, isKsk, 2048);
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity for a 
   * Data-Signing-Key and default keySize 2048.
   * @param identityName The name of the identity.
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPair(Name identityName) throws SecurityException
  {
    return generateRSAKeyPair(identityName, false, 2048);
  }

  /**
   * Set a key as the default key of an identity.
   * @param keyName The name of the key.
   * @param identityName the name of the identity. If empty, the 
   * identity name is inferred from the keyName.
   */
  public void
  setDefaultKeyForIdentity(Name keyName, Name identityName)
  {
    identityStorage_.setDefaultKeyNameForIdentity(keyName, identityName);
  }

  /**
   * Set a key as the default key of an identity, inferred from the keyName.
   * @param keyName The name of the key.
   */
  public void
  setDefaultKeyForIdentity(Name keyName)
  {
    setDefaultKeyForIdentity(keyName, new Name());
  }

  /**
   * Get the default key for an identity.
   * @param identityName the name of the identity. If empty, the identity name 
   * is inferred from the keyName.
   * @return The default key name.
   */
  public Name
  getDefaultKeyNameForIdentity(Name identityName)
  {
    return identityStorage_.getDefaultKeyNameForIdentity(identityName);
  }

  /**
   * Get the default key for an identity, inferred from the keyName.
   * @return The default key name.
   */
  public Name
  getDefaultKeyNameForIdentity()
  {
    return getDefaultKeyNameForIdentity(new Name());
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity and set it as 
   * default key for the identity.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keySize The size of the key.
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPairAsDefault
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, KeyType.RSA, keySize);

    identityStorage_.setDefaultKeyNameForIdentity(keyName, identityName);

    return keyName;
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity and set it as 
   * default key for the identity, using the default keySize 2048.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPairAsDefault(Name identityName, boolean isKsk) throws SecurityException
  {
    return generateRSAKeyPairAsDefault(identityName, isKsk, 2048);
  }
  
  /**
   * Generate a pair of RSA keys for the specified identity and set it as 
   * default key for the identity for a Data-Signing-Key and using the default 
   * keySize 2048.
   * @param identityName The name of the identity.
   * @return The generated key name.
   */
  public Name
  generateRSAKeyPairAsDefault(Name identityName) throws SecurityException
  {
    return generateRSAKeyPairAsDefault(identityName, false, 2048);
  }

  /**
   * Get the public key with the specified name.
   * @param keyName The name of the key.
   * @return The public key.
   */
  public PublicKey
  getPublicKey(Name keyName)
  {
    return PublicKey.fromDer(identityStorage_.getKey(keyName));
  }

  /**
   * Create an identity certificate for a public key managed by this IdentityManager.
   * @param certificatePrefix The name of public key to be signed.
   * @param signerCertificateName The name of signing certificate.
   * @param notBefore The notBefore value in the validity field of the 
   * generated certificate as milliseconds since 1970.
   * @param notAfter The notAfter value in validity field of the generated 
   * certificate as milliseconds since 1970.
   * @return The name of generated identity certificate.
   */
  public Name
  createIdentityCertificate
    (Name certificatePrefix, Name signerCertificateName, double notBefore, 
     double notAfter) throws SecurityException
  {
    Name keyName = getKeyNameFromCertificatePrefix(certificatePrefix);

    Blob keyBlob = identityStorage_.getKey(keyName);
    PublicKey publicKey = PublicKey.fromDer(keyBlob);

    IdentityCertificate certificate = createIdentityCertificate
      (certificatePrefix, publicKey,  signerCertificateName, notBefore, notAfter);

    identityStorage_.addCertificate(certificate);

    return certificate.getName();
  }

  /**
   * Create an identity certificate for a public key supplied by the caller.
   * @param certificatePrefix The name of public key to be signed.
   * @param publickey The public key to be signed.
   * @param signerCertificateName The name of signing certificate.
   * @param notBefore The notBefore value in the validity field of the generated certificate.
   * @param notAfter The notAfter vallue in validity field of the generated certificate.
   * @return The generated identity certificate.
   */
  public IdentityCertificate
  createIdentityCertificate
    (Name certificatePrefix, PublicKey publickey, Name signerCertificateName, 
     double notBefore, double notAfter)
  {
    throw new UnsupportedOperationException
      ("IdentityManager::createIdentityCertificate not implemented");
  }
    
  /**
   * Add a certificate into the public key identity storage.
   * @param certificate The certificate to to added.  This makes a copy of the 
   * certificate.
   */
  public void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    identityStorage_.addCertificate(certificate);
  }

  /**
   * Set the certificate as the default for its corresponding key.
   * @param certificateName The certificate.
   */
  public void
  setDefaultCertificateForKey
    (IdentityCertificate certificate) throws SecurityException
  {
    Name keyName = certificate.getPublicKeyName();

    if (!identityStorage_.doesKeyExist(keyName))
      throw new SecurityException("No corresponding Key record for certificate!");

    identityStorage_.setDefaultCertificateNameForKey
      (keyName, certificate.getName());
  }

  /**
   * Add a certificate into the public key identity storage and set the 
   * certificate as the default for its corresponding identity.
   * @param certificate The certificate to be added.  This makes a copy of the 
   * certificate.
   */
  public void
  addCertificateAsIdentityDefault(IdentityCertificate certificate) throws SecurityException
  {
    identityStorage_.addCertificate(certificate);

    Name keyName = certificate.getPublicKeyName();

    setDefaultKeyForIdentity(keyName);

    setDefaultCertificateForKey(certificate);
  }

  /**
   * Add a certificate into the public key identity storage and set the 
   * certificate as the default of its corresponding key.
   * @param certificate The certificate to be added.  This makes a copy of the 
   * certificate.
   */
  public void
  addCertificateAsDefault(IdentityCertificate certificate) throws SecurityException
  {
    identityStorage_.addCertificate(certificate);

    setDefaultCertificateForKey(certificate);
  }

  /**
   * Get a certificate with the specified name.
   * @param certificateName The name of the requested certificate.
   * @return the requested certificate which is valid.
   */
  public IdentityCertificate
  getCertificate(Name certificateName)
  {
    return new IdentityCertificate
      (identityStorage_.getCertificate(certificateName, false));
  }
    
  /**
   * Get a certificate even if the certificate is not valid anymore.
   * @param certificateName The name of the requested certificate.
   * @return the requested certificate.
   */
  public IdentityCertificate
  getAnyCertificate(Name certificateName)
  {
    return new IdentityCertificate
      (identityStorage_.getCertificate(certificateName, true));
  }
    
  /**
   * Get the default certificate name for the specified identity, which will be 
   * used when signing is performed based on identity.
   * @param identityName The name of the specified identity.
   * @return The requested certificate name.
   */
  public Name
  getDefaultCertificateNameForIdentity(Name identityName)
  {
    return identityStorage_.getDefaultCertificateNameForIdentity(identityName);
  }
    
  /**
   * Get the default certificate name of the default identity, which will be 
   * used when signing is based on identity and the identity is not specified.
   * @return The requested certificate name.
   * @throws SecurityException if the default identity is not set.
   */
  public Name
  getDefaultCertificateName() throws SecurityException
  {
    return identityStorage_.getDefaultCertificateNameForIdentity
      (getDefaultIdentity());
  }
        
  /**
   * Sign the byte array data based on the certificate name.
   * @param buffer The byte buffer to be signed.
   * @param certificateName The signing certificate name.
   * @return The generated signature.
   */
  public Signature
  signByCertificate(ByteBuffer buffer, Name certificateName) throws SecurityException
  {
    Name keyName = IdentityCertificate.certificateNameToPublicKeyName
      (certificateName);
    PublicKey publicKey = privateKeyStorage_.getPublicKey(keyName);

    Blob sigBits = privateKeyStorage_.sign(buffer, keyName);

    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Sha256WithRsaSignature sha256Sig = new Sha256WithRsaSignature();

    KeyLocator keyLocator = new KeyLocator();    
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(certificateName);

    sha256Sig.setKeyLocator(keyLocator);
    sha256Sig.getPublisherPublicKeyDigest().setPublisherPublicKeyDigest
      (publicKey.getDigest());
    sha256Sig.setSignature(sigBits);

    return sha256Sig;
  }

  /**
   * Sign data packet based on the certificate name.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param data The Data object to sign and update its signature.
   * @param certificateName The Name identifying the certificate which 
   * identifies the signing key.
   * @param wireFormat The WireFormat for calling encodeData.
   */
  public void 
  signByCertificate(Data data, Name certificateName) throws SecurityException
  {
    signByCertificate(data, certificateName, WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign data packet based on the certificate name.
   * @param data The Data object to sign and update its signature.
   * @param certificateName The Name identifying the certificate which 
   * identifies the signing key.
   * @param wireFormat The WireFormat for calling encodeData.
   */
  public void 
  signByCertificate
    (Data data, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    Name keyName = IdentityCertificate.certificateNameToPublicKeyName
      (certificateName);
    PublicKey publicKey = privateKeyStorage_.getPublicKey(keyName);

    // For temporary usage, we support RSA + SHA256 only, but will support more.
    data.setSignature(new Sha256WithRsaSignature());
    // Get a pointer to the clone which Data made.
    Sha256WithRsaSignature signature = (Sha256WithRsaSignature)data.getSignature();
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));
    // Ignore witness and leave the digestAlgorithm as the default.
    signature.getPublisherPublicKeyDigest().setPublisherPublicKeyDigest
      (publicKey.getDigest());

    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);

    signature.setSignature
      (privateKeyStorage_.sign(encoding.signedBuf(), keyName, digestAlgorithm));

    // Encode again to include the signature.
    data.wireEncode(wireFormat);
  }

  /**
   * Generate a self-signed certificate for a public key.
   * @param keyName The name of the public key.
   * @return The generated certificate.
   */
  IdentityCertificate
  selfSign(Name keyName)
  {
    throw new UnsupportedOperationException
      ("IdentityManager::selfSign not implemented");
  }

  /**
   * Generate a key pair for the specified identity.
   * @param identityName The name of the specified identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keyType The type of the key pair, e.g. KEY_TYPE_RSA.
   * @param keySize The size of the key pair.
   * @return The name of the generated key.
   */
  private Name
  generateKeyPair
    (Name identityName, boolean isKsk, KeyType keyType, 
     int keySize) throws SecurityException
  {
    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Get new key ID");    
    Name keyName = identityStorage_.getNewKeyName(identityName, isKsk);

    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Generate key pair in private storage");
    privateKeyStorage_.generateKeyPair(keyName, keyType, keySize);

    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Create a key record in public storage");
    PublicKey pubKey = privateKeyStorage_.getPublicKey(keyName);
    identityStorage_.addKey(keyName, keyType, pubKey.getKeyDer());

    return keyName;
  }

  private static Name
  getKeyNameFromCertificatePrefix(Name certificatePrefix) throws SecurityException
  {
    Name result = new Name();

    String keyString = "KEY";
    int i = 0;
    for(; i < certificatePrefix.size(); i++) {
      if (certificatePrefix.get(i).toEscapedString().equals(keyString))
        break;
    }

    if (i >= certificatePrefix.size())
      throw new SecurityException
        ("Identity Certificate Prefix does not have a KEY component");

    result.append(certificatePrefix.getSubName(0, i));
    result.append
      (certificatePrefix.getSubName(i + 1, certificatePrefix.size()-i-1));

    return result;
  }

  private IdentityStorage identityStorage_;
  private PrivateKeyStorage privateKeyStorage_;
}
