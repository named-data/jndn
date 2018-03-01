/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.EcKeyParams;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.CertificateSubjectDescription;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.ConfigFile;
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
    // Don't call checkTpm() when using a custom PrivateKeyStorage.
  }

  /**
   * Create a new IdentityManager to use the given IdentityStorage and
   * the default PrivateKeyStorage for your system, which is
   * OSXPrivateKeyStorage for OS X, otherwise FilePrivateKeyStorage.
   * @param identityStorage An object of a subclass of IdentityStorage.
   */
  public IdentityManager(IdentityStorage identityStorage) throws SecurityException
  {
    ConfigFile config;
    try {
      config = new ConfigFile();
    } catch (IOException ex) {
      throw new SecurityException("IOException " + ex.getMessage());
    }

    String[] canonicalTpmLocator = new String[] { null };
    identityStorage_ = identityStorage;
    privateKeyStorage_ = getDefaultPrivateKeyStorage(config, canonicalTpmLocator);

    checkTpm(canonicalTpmLocator[0]);
  }

  /**
   * Create a new IdentityManager to use BasicIdentityStorage and
   * the default PrivateKeyStorage for your system, which is
   * OSXPrivateKeyStorage for OS X, otherwise FilePrivateKeyStorage.
   */
  public IdentityManager() throws SecurityException
  {
    ConfigFile config;
    try {
      config = new ConfigFile();
    } catch (IOException ex) {
      throw new SecurityException("IOException " + ex.getMessage());
    }

    String[] canonicalTpmLocator = new String[] { null };
    identityStorage_ = getDefaultIdentityStorage(config);
    privateKeyStorage_ = getDefaultPrivateKeyStorage(config, canonicalTpmLocator);

    checkTpm(canonicalTpmLocator[0]);
  }

  /**
   * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
   * identity and a self-signed certificate of the KSK. If a key pair or
   * certificate for the identity already exists, use it.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the identity.
   * @return The name of the default certificate of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public final Name
  createIdentityAndCertificate(Name identityName, KeyParams params)
    throws SecurityException
  {
    identityStorage_.addIdentity(identityName);

    Name keyName = null;
    boolean generateKey = true;
    try {
      keyName = identityStorage_.getDefaultKeyNameForIdentity(identityName);
      PublicKey key = new PublicKey(identityStorage_.getKey(keyName));
      if (key.getKeyType() == params.getKeyType())
        // The key exists and has the same type, so don't need to generate one.
        generateKey = false;
    } catch (SecurityException ex) {}

    if (generateKey) {
      keyName = generateKeyPair(identityName, true, params);
      identityStorage_.setDefaultKeyNameForIdentity(keyName);
    }

    Name certName = null;
    boolean makeCert = true;
    try {
      certName = identityStorage_.getDefaultCertificateNameForKey(keyName);
      // The cert exists, so don't need to make it.
      makeCert = false;
    } catch (SecurityException ex) {}

    if (makeCert) {
      IdentityCertificate selfCert = selfSign(keyName);
      addCertificateAsIdentityDefault(selfCert);
      certName = selfCert.getName();
    }

    return certName;
  }

  /**
   * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
   * identity and a self-signed certificate of the KSK.
   * @deprecated Use createIdentityAndCertificate which returns the
   * certificate name instead of the key name. You can use
   * IdentityCertificate.certificateNameToPublicKeyName to convert the
   * certificate name to the key name.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the identity.
   * @return The key name of the auto-generated KSK of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public final Name
  createIdentity(Name identityName, KeyParams params) throws SecurityException
  {
    return IdentityCertificate.certificateNameToPublicKeyName
      (createIdentityAndCertificate(identityName, params));
  }

  /**
   * Delete the identity from the public and private key storage. If the
   * identity to be deleted is the current default system default, this will not
   * delete the identity and will return immediately.
   * @param identityName The name of the identity.
   */
  public final void
  deleteIdentity(Name identityName) throws SecurityException
  {
    try {
      if (identityStorage_.getDefaultIdentity().equals(identityName))
        // Don't delete the default identity!
        return;
    }
    catch (SecurityException ex) {
      // There is no default identity to check.
    }

    // Use ArrayList without generics so it works with older Java compilers.
    ArrayList keysToDelete = new ArrayList();
    identityStorage_.getAllKeyNamesOfIdentity(identityName, keysToDelete, true);
    identityStorage_.getAllKeyNamesOfIdentity(identityName, keysToDelete, false);

    identityStorage_.deleteIdentityInfo(identityName);

    for (int i = 0; i < keysToDelete.size(); ++i)
      privateKeyStorage_.deleteKeyPair((Name)keysToDelete.get(i));
  }

  /**
   * Set the default identity.  If the identityName does not exist, then clear
   * the default identity so that getDefaultIdentity() throws an exception.
   * @param identityName The default identity name.
   */
  public final void
  setDefaultIdentity(Name identityName) throws SecurityException
  {
    identityStorage_.setDefaultIdentity(identityName);
  }

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public final Name
  getDefaultIdentity() throws SecurityException
  {
    return identityStorage_.getDefaultIdentity();
  }

  /**
   * Get the certificate of the default identity.
   * @return The requested certificate. If not found, return null.
   */
  public final IdentityCertificate
  getDefaultCertificate() throws SecurityException
  {
    return identityStorage_.getDefaultCertificate();
  }

  /**
   * Generate a pair of RSA keys for the specified identity.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keySize The size of the key.
   * @return The generated key name.
   */
  public final Name
  generateRSAKeyPair
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, new RsaKeyParams(keySize));

    return keyName;
  }

  /**
   * Generate a pair of RSA keys for the specified identity and default keySize
   * 2048.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public final Name
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
  public final Name
  generateRSAKeyPair(Name identityName) throws SecurityException
  {
    return generateRSAKeyPair(identityName, false, 2048);
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keySize The size of the key.
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPair
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, new EcKeyParams(keySize));

    return keyName;
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity and default keySize
   * 256.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPair(Name identityName, boolean isKsk) throws SecurityException
  {
    return generateEcdsaKeyPair(identityName, isKsk, 256);
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity for a
   * Data-Signing-Key and default keySize 256.
   * @param identityName The name of the identity.
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPair(Name identityName) throws SecurityException
  {
    return generateEcdsaKeyPair(identityName, false, 256);
  }

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   * @param identityNameCheck The identity name to check that the keyName
   * contains the same identity name. If an empty name, it is ignored.
   */
  public final void
  setDefaultKeyForIdentity(Name keyName, Name identityNameCheck) throws SecurityException
  {
    identityStorage_.setDefaultKeyNameForIdentity(keyName, identityNameCheck);
  }

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   */
  public final void
  setDefaultKeyForIdentity(Name keyName) throws SecurityException
  {
    setDefaultKeyForIdentity(keyName, new Name());
  }

  /**
   * Get the default key for an identity.
   * @param identityName the name of the identity. If empty, the identity name
   * is inferred from the keyName.
   * @return The default key name.
   * @throws SecurityException if the default key name for the identity is not set.
   */
  public final Name
  getDefaultKeyNameForIdentity(Name identityName) throws SecurityException
  {
    return identityStorage_.getDefaultKeyNameForIdentity(identityName);
  }

  /**
   * Get the default key for an identity, inferred from the keyName.
   * @return The default key name.
   * @throws SecurityException if the default key name for the identity is not set.
   */
  public final Name
  getDefaultKeyNameForIdentity() throws SecurityException
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
  public final Name
  generateRSAKeyPairAsDefault
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, new RsaKeyParams(keySize));

    identityStorage_.setDefaultKeyNameForIdentity(keyName);

    return keyName;
  }

  /**
   * Generate a pair of RSA keys for the specified identity and set it as
   * default key for the identity, using the default keySize 2048.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public final Name
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
  public final Name
  generateRSAKeyPairAsDefault(Name identityName) throws SecurityException
  {
    return generateRSAKeyPairAsDefault(identityName, false, 2048);
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity and set it as
   * default key for the identity.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param keySize The size of the key.
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPairAsDefault
    (Name identityName, boolean isKsk, int keySize) throws SecurityException
  {
    Name keyName = generateKeyPair(identityName, isKsk, new EcKeyParams(keySize));

    identityStorage_.setDefaultKeyNameForIdentity(keyName);

    return keyName;
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity and set it as
   * default key for the identity, using the default keySize 256.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPairAsDefault(Name identityName, boolean isKsk) throws SecurityException
  {
    return generateEcdsaKeyPairAsDefault(identityName, isKsk, 256);
  }

  /**
   * Generate a pair of ECDSA keys for the specified identity and set it as
   * default key for the identity for a Data-Signing-Key and using the default
   * keySize 256.
   * @param identityName The name of the identity.
   * @return The generated key name.
   */
  public final Name
  generateEcdsaKeyPairAsDefault(Name identityName) throws SecurityException
  {
    return generateEcdsaKeyPairAsDefault(identityName, false, 256);
  }

  /**
   * Get the public key with the specified name.
   * @param keyName The name of the key.
   * @return The public key.
   * @throws SecurityException if the keyName is not found.
   */
  public final PublicKey
  getPublicKey(Name keyName) throws SecurityException
  {
    return new PublicKey(identityStorage_.getKey(keyName));
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
  public final Name
  createIdentityCertificate
    (Name certificatePrefix, Name signerCertificateName, double notBefore,
     double notAfter) throws SecurityException
  {
    Name keyName = getKeyNameFromCertificatePrefix(certificatePrefix);

    Blob keyBlob = identityStorage_.getKey(keyName);
    PublicKey publicKey = new PublicKey(keyBlob);

    IdentityCertificate certificate = createIdentityCertificate
      (certificatePrefix, publicKey,  signerCertificateName, notBefore, notAfter);

    identityStorage_.addCertificate(certificate);

    return certificate.getName();
  }

  /**
   * Use the keyName to get the public key from the identity storage and
   * prepare an unsigned identity certificate.
   * @param keyName The key name, e.g., `/{identity_name}/ksk-123456`.
   * @param signingIdentity The signing identity.
   * @param notBefore See IdentityCertificate.
   * @param notAfter See IdentityCertificate.
   * @param subjectDescription A list of CertificateSubjectDescription. See
   * IdentityCertificate. If null or empty, this adds a an ATTRIBUTE_NAME based
   * on the keyName.
   * @param certPrefix The prefix before the `KEY` component. If null, this
   * infers the certificate name according to the relation between the
   * signingIdentity and the subject identity. If the signingIdentity is a
   * prefix of the subject identity, `KEY` will be inserted after the
   * signingIdentity, otherwise `KEY` is inserted after subject identity (i.e.,
   * before `ksk-...`).
   * @return The unsigned IdentityCertificate, or null the public is not in the
   * identity storage or if the inputs are invalid.
   */
  public final IdentityCertificate
  prepareUnsignedIdentityCertificate
    (Name keyName, Name signingIdentity, double notBefore, double notAfter,
     List subjectDescription, Name certPrefix)
    throws SecurityException
  {
    PublicKey publicKey;
    try {
      publicKey = new PublicKey(identityStorage_.getKey(keyName));
    }
    catch (SecurityException e) {
      return null;
    }

    return prepareUnsignedIdentityCertificate
      (keyName, publicKey, signingIdentity, notBefore, notAfter,
       subjectDescription, certPrefix);
  }

  /**
   * Use the keyName to get the public key from the identity storage and
   * prepare an unsigned identity certificate. This infers the certificate name
   * according to the relation between the signingIdentity and the subject
   * identity. If the signingIdentity is a prefix of the subject identity, `KEY`
   * will be inserted after the signingIdentity, otherwise `KEY` is inserted
   * after subject identity (i.e., before `ksk-...`).
   * @param keyName The key name, e.g., `/{identity_name}/ksk-123456`.
   * @param signingIdentity The signing identity.
   * @param notBefore See IdentityCertificate.
   * @param notAfter See IdentityCertificate.
   * @param subjectDescription A list of CertificateSubjectDescription. See
   * IdentityCertificate. If null or empty, this adds a an ATTRIBUTE_NAME based
   * on the keyName.
   * @return The unsigned IdentityCertificate, or null the public is not in the
   * identity storage or if the inputs are invalid.
   */
  public final IdentityCertificate
  prepareUnsignedIdentityCertificate
    (Name keyName, Name signingIdentity, double notBefore, double notAfter,
     List subjectDescription)
    throws SecurityException
  {
    return prepareUnsignedIdentityCertificate
      (keyName, signingIdentity, notBefore, notAfter, subjectDescription, null);
  }

  /**
   * Prepare an unsigned identity certificate.
   * @param keyName The key name, e.g., `/{identity_name}/ksk-123456`.
   * @param publicKey The public key to sign.
   * @param signingIdentity The signing identity.
   * @param notBefore See IdentityCertificate.
   * @param notAfter See IdentityCertificate.
   * @param subjectDescription A list of CertificateSubjectDescription. See
   * IdentityCertificate. If null or empty, this adds a an ATTRIBUTE_NAME based
   * on the keyName.
   * @param certPrefix The prefix before the `KEY` component. If null, this
   * infers the certificate name according to the relation between the
   * signingIdentity and the subject identity. If the signingIdentity is a
   * prefix of the subject identity, `KEY` will be inserted after the
   * signingIdentity, otherwise `KEY` is inserted after subject identity (i.e.,
   * before `ksk-...`).
   * @return The unsigned IdentityCertificate, or null if the inputs are invalid.
   */
  public final IdentityCertificate
  prepareUnsignedIdentityCertificate
    (Name keyName, PublicKey publicKey, Name signingIdentity, double notBefore,
     double notAfter, List subjectDescription, Name certPrefix)
    throws SecurityException
  {
    if (keyName.size() < 1)
      return null;

    String tempKeyIdPrefix = keyName.get(-1).toEscapedString();
    if (tempKeyIdPrefix.length() < 4)
      return null;
    String keyIdPrefix = tempKeyIdPrefix.substring(0, 4);
    if (!keyIdPrefix.equals("ksk-") && !keyIdPrefix.equals("dsk-"))
      return null;

    IdentityCertificate certificate = new IdentityCertificate();
    Name certName = new Name();

    if (certPrefix == null) {
      // No certificate prefix hint, so infer the prefix.
      if (signingIdentity.match(keyName))
        certName.append(signingIdentity)
          .append("KEY")
          .append(keyName.getSubName(signingIdentity.size()))
          .append("ID-CERT")
          .appendVersion((long)Common.getNowMilliseconds());
      else
        certName.append(keyName.getPrefix(-1))
          .append("KEY")
          .append(keyName.get(-1))
          .append("ID-CERT")
          .appendVersion((long)Common.getNowMilliseconds());
    }
    else {
      // A cert prefix hint is supplied, so determine the cert name.
      if (certPrefix.match(keyName) && !certPrefix.equals(keyName))
        certName.append(certPrefix)
          .append("KEY")
          .append(keyName.getSubName(certPrefix.size()))
          .append("ID-CERT")
          .appendVersion((long)Common.getNowMilliseconds());
      else
        return null;
    }

    certificate.setName(certName);
    certificate.setNotBefore(notBefore);
    certificate.setNotAfter(notAfter);
    certificate.setPublicKeyInfo(publicKey);

    if (subjectDescription == null || subjectDescription.isEmpty())
      certificate.addSubjectDescription(new CertificateSubjectDescription
        ("2.5.4.41", keyName.getPrefix(-1).toUri()));
    else {
      for (int i = 0; i < subjectDescription.size(); ++i)
        certificate.addSubjectDescription
          ((CertificateSubjectDescription)subjectDescription.get(i));
    }

    try {
      certificate.encode();
    } catch (DerEncodingException ex) {
      throw new SecurityException("DerEncodingException: " + ex);
    } catch (DerDecodingException ex) {
      throw new SecurityException("DerDecodingException: " + ex);
    }

    return certificate;
  }

  /**
   * Prepare an unsigned identity certificate. This infers the certificate name
   * according to the relation between the signingIdentity and the subject
   * identity. If the signingIdentity is a prefix of the subject identity, `KEY`
   * will be inserted after the signingIdentity, otherwise `KEY` is inserted
   * after subject identity (i.e., before `ksk-...`).
   * @param keyName The key name, e.g., `/{identity_name}/ksk-123456`.
   * @param publicKey The public key to sign.
   * @param signingIdentity The signing identity.
   * @param notBefore See IdentityCertificate.
   * @param notAfter See IdentityCertificate.
   * @param subjectDescription A list of CertificateSubjectDescription. See
   * IdentityCertificate. If null or empty, this adds a an ATTRIBUTE_NAME based
   * on the keyName.
   * @return The unsigned IdentityCertificate, or null if the inputs are invalid.
   */
  public final IdentityCertificate
  prepareUnsignedIdentityCertificate
    (Name keyName, PublicKey publicKey, Name signingIdentity, double notBefore,
     double notAfter, List subjectDescription)
    throws SecurityException
  {
    return prepareUnsignedIdentityCertificate
      (keyName, publicKey, signingIdentity, notBefore, notAfter,
       subjectDescription, null);
  }

  /**
   * Create an identity certificate for a public key supplied by the caller.
   * @param certificatePrefix The name of public key to be signed.
   * @param publicKey The public key to be signed.
   * @param signerCertificateName The name of signing certificate.
   * @param notBefore The notBefore value in the validity field of the generated certificate.
   * @param notAfter The notAfter vallue in validity field of the generated certificate.
   * @return The generated identity certificate.
   */
  public final IdentityCertificate
  createIdentityCertificate
    (Name certificatePrefix, PublicKey publicKey, Name signerCertificateName,
     double notBefore, double notAfter) throws SecurityException
  {
    IdentityCertificate certificate = new IdentityCertificate();
    Name keyName = getKeyNameFromCertificatePrefix(certificatePrefix);

    Name certificateName = new Name(certificatePrefix);
    certificateName.append("ID-CERT")
      .appendVersion((long)Common.getNowMilliseconds());

    certificate.setName(certificateName);
    certificate.setNotBefore(notBefore);
    certificate.setNotAfter(notAfter);
    certificate.setPublicKeyInfo(publicKey);
    certificate.addSubjectDescription
      (new CertificateSubjectDescription("2.5.4.41", keyName.toUri()));
    try {
      certificate.encode();
    } catch (DerEncodingException ex) {
      throw new SecurityException("DerDecodingException: " + ex);
    } catch (DerDecodingException ex) {
      throw new SecurityException("DerEncodingException: " + ex);
    }

    Sha256WithRsaSignature sha256Sig = new Sha256WithRsaSignature();

    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(signerCertificateName);

    sha256Sig.setKeyLocator(keyLocator);

    certificate.setSignature(sha256Sig);

    SignedBlob unsignedData = certificate.wireEncode();

    IdentityCertificate signerCertificate;
    try {
      signerCertificate = getCertificate(signerCertificateName);
    } catch (DerDecodingException ex) {
      throw new SecurityException("DerDecodingException: " + ex);
    }
    Name signerkeyName = signerCertificate.getPublicKeyName();

    Blob sigBits = privateKeyStorage_.sign
      (unsignedData.signedBuf(), signerkeyName);

    sha256Sig.setSignature(sigBits);

    return certificate;
  }

  /**
   * Add a certificate into the public key identity storage.
   * @param certificate The certificate to to added.  This makes a copy of the
   * certificate.
   */
  public final void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    identityStorage_.addCertificate(certificate);
  }

  /**
   * Set the certificate as the default for its corresponding key.
   * @param certificate The certificate.
   */
  public final void
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
  public final void
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
  public final void
  addCertificateAsDefault(IdentityCertificate certificate) throws SecurityException
  {
    identityStorage_.addCertificate(certificate);

    setDefaultCertificateForKey(certificate);
  }

  /**
   * Get a certificate with the specified name.
   * @param certificateName The name of the requested certificate.
   * @return the requested certificate.
   */
  public final IdentityCertificate
  getCertificate(Name certificateName) throws SecurityException, DerDecodingException
  {
    return identityStorage_.getCertificate(certificateName);
  }

  /**
   * Get the default certificate name for the specified identity, which will be
   * used when signing is performed based on identity.
   * @param identityName The name of the specified identity.
   * @return The requested certificate name.
   * @throws SecurityException if the default key name for the identity is not
   * set or the default certificate name for the key name is not set.
   */
  public final Name
  getDefaultCertificateNameForIdentity(Name identityName) throws SecurityException
  {
    return identityStorage_.getDefaultCertificateNameForIdentity(identityName);
  }

  /**
   * Get the default certificate name of the default identity, which will be
   * used when signing is based on identity and the identity is not specified.
   * @return The requested certificate name.
   * @throws SecurityException if the default identity is not set or the default
   * key name for the identity is not set or the default certificate name for
   * the key name is not set.
   */
  public final Name
  getDefaultCertificateName() throws SecurityException
  {
    return identityStorage_.getDefaultCertificateNameForIdentity
      (getDefaultIdentity());
  }

  /**
   * Append all the identity names to the nameList.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default identity name. If false, add
   * only the non-default identity names.
   */
  public void
  getAllIdentities(ArrayList nameList, boolean isDefault)
    throws SecurityException
  {
    identityStorage_.getAllIdentities(nameList, isDefault);
  }

  /**
   * Append all the key names of a particular identity to the nameList.
   * @param identityName The identity name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default key name. If false, add only
   * the non-default key names.
   */
  public final void
  getAllKeyNamesOfIdentity
    (Name identityName, ArrayList nameList, boolean isDefault)
    throws SecurityException
  {
    identityStorage_.getAllKeyNamesOfIdentity(identityName, nameList, isDefault);
  }

  /**
   * Append all the certificate names of a particular key name to the nameList.
   * @param keyName The key name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default certificate name. If false,
   * add only the non-default certificate names.
   */
  public void
  getAllCertificateNamesOfKey
    (Name keyName, ArrayList nameList, boolean isDefault) throws SecurityException
  {
    identityStorage_.getAllCertificateNamesOfKey(keyName, nameList, isDefault);
  }

  /**
   * Sign the byte array data based on the certificate name.
   * @param buffer The byte buffer to be signed.
   * @param certificateName The signing certificate name.
   * @return The generated signature.
   */
  public final Signature
  signByCertificate(ByteBuffer buffer, Name certificateName) throws SecurityException
  {
    DigestAlgorithm[] digestAlgorithm = new DigestAlgorithm[1];
    Signature signature = makeSignatureByCertificate
      (certificateName, digestAlgorithm);

    signature.setSignature(privateKeyStorage_.sign(buffer,
      IdentityCertificate.certificateNameToPublicKeyName(certificateName),
      digestAlgorithm[0]));

    return signature;
  }

  /**
   * Sign data packet based on the certificate name.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param data The Data object to sign and update its signature.
   * @param certificateName The Name identifying the certificate which
   * identifies the signing key.
   */
  public final void
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
  public final void
  signByCertificate
    (Data data, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    DigestAlgorithm[] digestAlgorithm = new DigestAlgorithm[1];
    Signature signature = makeSignatureByCertificate
      (certificateName, digestAlgorithm);

    data.setSignature(signature);
    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);

    data.getSignature().setSignature
      (privateKeyStorage_.sign(encoding.signedBuf(),
       IdentityCertificate.certificateNameToPublicKeyName(certificateName),
       digestAlgorithm[0]));

    // Encode again to include the signature.
    data.wireEncode(wireFormat);
  }

  /**
   * Append a SignatureInfo to the Interest name, sign the name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param certificateName The certificate name of the key to use for signing.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public final void
  signInterestByCertificate
    (Interest interest, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    DigestAlgorithm[] digestAlgorithm = new DigestAlgorithm[1];
    Signature signature = makeSignatureByCertificate
      (certificateName, digestAlgorithm);

    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signature));

    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());
    // Encode once to get the signed portion, and sign.
    SignedBlob encoding = interest.wireEncode(wireFormat);
    signature.setSignature
      (privateKeyStorage_.sign(encoding.signedBuf(),
       IdentityCertificate.certificateNameToPublicKeyName(certificateName),
       digestAlgorithm[0]));

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
  }

  /**
   * Wire encode the Data object, digest it and set its SignatureInfo to
   * a DigestSha256.
   * @param data The Data object to be signed. This updates its signature and
   * wireEncoding.
   * @param wireFormat The WireFormat for calling encodeData.
   */
  public final void
  signWithSha256(Data data, WireFormat wireFormat)
  {
    data.setSignature(new DigestSha256Signature());

    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);

    // Digest and set the signature.
    byte[] signedPortionDigest = Common.digestSha256(encoding.signedBuf());
    data.getSignature().setSignature(new Blob(signedPortionDigest, false));

    // Encode again to include the signature.
    data.wireEncode(wireFormat);
  }

  /**
   * Append a SignatureInfo for DigestSha256 to the Interest name, digest the
   * name components and append a final name component with the signature bits
   * (which is the digest).
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public final void
  signInterestWithSha256(Interest interest, WireFormat wireFormat)
  {
    DigestSha256Signature signature = new DigestSha256Signature();
    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signature));

    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());
    // Encode once to get the signed portion.
    SignedBlob encoding = interest.wireEncode(wireFormat);

    // Digest and set the signature.
    byte[] signedPortionDigest = Common.digestSha256(encoding.signedBuf());
    signature.setSignature(new Blob(signedPortionDigest, false));

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
  }

  /**
   * Generate a self-signed certificate for a public key.
   * @param keyName The name of the public key.
   * @return The generated certificate.
   */
  public IdentityCertificate
  selfSign(Name keyName) throws SecurityException
  {
    IdentityCertificate certificate = new IdentityCertificate();

    Blob keyBlob = identityStorage_.getKey(keyName);
    PublicKey publicKey = new PublicKey(keyBlob);

    Calendar calendar = Calendar.getInstance();
    double notBefore = (double)calendar.getTimeInMillis();
    calendar.add(Calendar.YEAR, 2);
    double notAfter = (double)calendar.getTimeInMillis();

    certificate.setNotBefore(notBefore);
    certificate.setNotAfter(notAfter);

    Name certificateName = keyName.getPrefix(-1).append("KEY").append
      (keyName.get(-1)).append("ID-CERT").appendVersion
      ((long)certificate.getNotBefore());
    certificate.setName(certificateName);

    certificate.setPublicKeyInfo(publicKey);
    certificate.addSubjectDescription(new CertificateSubjectDescription
      ("2.5.4.41", keyName.toUri()));
    try {
      certificate.encode();
    } catch (DerEncodingException ex) {
      // We don't expect this to happen.
      Logger.getLogger(IdentityManager.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    } catch (DerDecodingException ex) {
      // We don't expect this to happen.
      Logger.getLogger(IdentityManager.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }

    signByCertificate(certificate, certificate.getName());

    return certificate;
  }

  /**
   * Generate a key pair for the specified identity.
   * @param identityName The name of the specified identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @param params The parameters of the key.
   * @return The name of the generated key.
   */
  private Name
  generateKeyPair
    (Name identityName, boolean isKsk, KeyParams params) throws SecurityException
  {
    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Get new key ID");
    Name keyName = identityStorage_.getNewKeyName(identityName, isKsk);

    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Generate key pair in private storage");
    privateKeyStorage_.generateKeyPair(keyName, params);

    Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "Create a key record in public storage");
    PublicKey pubKey = privateKeyStorage_.getPublicKey(keyName);
    identityStorage_.addKey(keyName, params.getKeyType(), pubKey.getKeyDer());

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

  /**
   * Return a new Signature object based on the signature algorithm of the
   * public key with keyName (derived from certificateName).
   * @param certificateName The certificate name.
   * @param digestAlgorithm Set digestAlgorithm[0] to the signature algorithm's
   * digest algorithm, e.g. DigestAlgorithm.SHA256.
   * @return A new object of the correct subclass of Signature.
   */
  private Signature
  makeSignatureByCertificate
    (Name certificateName, DigestAlgorithm[] digestAlgorithm) throws SecurityException
  {
    Name keyName = IdentityCertificate.certificateNameToPublicKeyName
      (certificateName);
    PublicKey publicKey = privateKeyStorage_.getPublicKey(keyName);
    KeyType keyType = publicKey.getKeyType();

    if (keyType == KeyType.RSA) {
      Sha256WithRsaSignature signature = new Sha256WithRsaSignature();
      digestAlgorithm[0] = DigestAlgorithm.SHA256;

      signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
      signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

      return signature;
    }
    else if (keyType == KeyType.EC) {
      Sha256WithEcdsaSignature signature = new Sha256WithEcdsaSignature();
      digestAlgorithm[0] = DigestAlgorithm.SHA256;

      signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
      signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

      return signature;
    }
    else
      throw new SecurityException("Key type is not recognized");
  }

  /**
   * Get the IdentityStorage from the pib value in the configuration file if
   * supplied. Otherwise, get the default for this platform.
   * @param config The configuration file to check.
   * @return A new IdentityStorage.
   */
  private static IdentityStorage
  getDefaultIdentityStorage(ConfigFile config) throws SecurityException
  {
    String pibLocator = config.get("pib", "");

    if (!pibLocator.equals("")) {
      // Don't support non-default locations for now.
      if (!pibLocator.equals("pib-sqlite3"))
        throw new SecurityException
          ("Invalid config file pib value: " + pibLocator);
    }

    return new BasicIdentityStorage();
  }

  /**
   * Get the PrivateKeyStorage from the tpm value in the configuration file if
   * supplied. Otherwise, get the default for this platform.
   * @param config The configuration file to check.
   * @param canonicalTpmLocator Set canonicalTpmLocator[0] to the canonical value
   * including the colon, * e.g. "tpm-file:".
   * @return A new PrivateKeyStorage.
   */
  private static PrivateKeyStorage
  getDefaultPrivateKeyStorage
    (ConfigFile config, String[] canonicalTpmLocator) throws SecurityException
  {
    String tpmLocator = config.get("tpm", "");

    if (tpmLocator.equals("")) {
      // Use the system default.
      if (Common.platformIsOSX()) {
        canonicalTpmLocator[0] = "tpm-osxkeychain:";
        throw new SecurityException
          ("OSXPrivateKeyStorage is not implemented yet. You must create an IdentityManager with a different PrivateKeyStorage.");
      }
      else {
        canonicalTpmLocator[0] = "tpm-file:";
        return new FilePrivateKeyStorage();
      }
    }
    else if (tpmLocator.equals("tpm-osxkeychain")) {
      canonicalTpmLocator[0] = "tpm-osxkeychain:";
      throw new SecurityException
        ("OSXPrivateKeyStorage is not implemented yet. You must create an IdentityManager with a different PrivateKeyStorage.");
    }
    else if (tpmLocator.equals("tpm-file")) {
      // Don't support non-default locations for now.
      canonicalTpmLocator[0] = "tpm-file:";
      return new FilePrivateKeyStorage();
    }
    else
      throw new SecurityException
        ("Invalid config file tpm value: " + tpmLocator);
  }

  /**
   * Check that identityStorage_.getTpmLocator() (if defined) matches the
   * canonicalTpmLocator.
   * @param canonicalTpmLocator The canonical locator from
   * getDefaultPrivateKeyStorage().
   * @throws SecurityException if the private key storage does not match.
   */
  private void
  checkTpm(String canonicalTpmLocator) throws SecurityException
  {
    String tpmLocator;
    try {
      tpmLocator = identityStorage_.getTpmLocator();
    } catch (SecurityException ex) {
      // The TPM locator is not set in PIB yet.
      return;
    }

    // Just check. If a PIB reset is required, expect ndn-cxx/NFD to do it.
    if (!tpmLocator.equals("") && !tpmLocator.equals(canonicalTpmLocator))
      throw new SecurityException
        ("The TPM locator supplied does not match the TPM locator in the PIB: " +
         tpmLocator + " != " + canonicalTpmLocator);
  }

  private final IdentityStorage identityStorage_;
  private final PrivateKeyStorage privateKeyStorage_;
}
