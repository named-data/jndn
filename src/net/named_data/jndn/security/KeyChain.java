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

package net.named_data.jndn.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Face;
import net.named_data.jndn.HmacWithSha256Signature;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.security.SigningInfo.SignerType;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.identity.BasicIdentityStorage;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.pib.PibSqlite3;
import net.named_data.jndn.security.policy.NoVerifyPolicyManager;
import net.named_data.jndn.security.policy.PolicyManager;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.tpm.TpmBackEndFile;
import net.named_data.jndn.security.tpm.TpmBackEndMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.ConfigFile;
import net.named_data.jndn.util.SignedBlob;

/**
 * KeyChain is the main class of the security library.
 *
 * The KeyChain class provides a set of interfaces to the security library such
 * as identity management, policy configuration and packet signing and
 * verification.
 * @note This class is an experimental feature.  See the API docs for more
 * detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 */
public class KeyChain {
  /**
   * A KeyChain.Error extends Exception and represents an error in KeyChain
   * processing.
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
   * A KeyChain.InvalidSigningInfoError extends KeyChain.Error to indicate
   * that the supplied SigningInfo is invalid.
   */
  public static class InvalidSigningInfoError extends KeyChain.Error {
    public InvalidSigningInfoError(String message)
    {
      super(message);
    }
  }

  /**
   * A KeyChain.LocatorMismatchError extends KeyChain.Error to indicate that
   * the supplied TPM locator does not match the locator stored in the PIB.
   */
  public static class LocatorMismatchError extends KeyChain.Error {
    public LocatorMismatchError(String message)
    {
      super(message);
    }
  }

  public interface MakePibImpl {
    PibImpl makePibImpl(String location) throws PibImpl.Error;
  }

  public interface MakeTpmBackEnd {
    TpmBackEnd makeTpmBackEnd(String location);
  }

  /**
   * Create a KeyChain to use the PIB and TPM defined by the given locators.
   * This creates a security v2 KeyChain that uses CertificateV2, Pib, Tpm and
   * Validator (instead of v1 Certificate, IdentityStorage, PrivateKeyStorage
   * and PolicyManager).
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @param allowReset If true, the PIB will be reset when the supplied
   * tpmLocator mismatches the one in the PIB.
   * @throws KeyChain.LocatorMismatchError if the supplied TPM locator does not
   * match the locator stored in the PIB.
   */
  public KeyChain(String pibLocator, String tpmLocator, boolean allowReset)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    isSecurityV1_ = false;
    construct(pibLocator, tpmLocator, allowReset);
  }

  /**
   * Create a KeyChain to use the PIB and TPM defined by the given locators.
   * Don't allow resetting the PIB when the supplied tpmLocator mismatches the
   * one in the PIB.
   * This creates a security v2 KeyChain that uses CertificateV2, Pib, Tpm and
   * Validator (instead of v1 Certificate, IdentityStorage, PrivateKeyStorage
   * and PolicyManager).
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @throws KeyChain.LocatorMismatchError if the supplied TPM locator does not
   * match the locator stored in the PIB.
   */
  public KeyChain(String pibLocator, String tpmLocator)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    isSecurityV1_ = false;
    construct(pibLocator, tpmLocator, false);
  }

  /**
   * Create a security v2 KeyChain with explicitly-created PIB and TPM objects,
   * and that still uses the v1 PolicyManager.
   * @param pibImpl An explicitly-created PIB object of a subclass of PibImpl.
   * @param tpmBackEnd An explicitly-created TPM object of a subclass of
   * TpmBackEnd.
   * @param policyManager An object of a subclass of a security v1 PolicyManager.
   */
  public KeyChain
    (PibImpl pibImpl, TpmBackEnd tpmBackEnd, PolicyManager policyManager)
    throws PibImpl.Error
  {
    isSecurityV1_ = false;
    policyManager_ = policyManager;

    pib_ = new Pib("", "", pibImpl);
    tpm_ = new Tpm("", "", tpmBackEnd);
  }

  /**
   * Create a security v2 KeyChain with explicitly-created PIB and TPM objects.
   * This sets the policy manager to a security v1 NoVerifyPolicyManager.
   * @param pibImpl An explicitly-created PIB object of a subclass of PibImpl.
   * @param tpmBackEnd An explicitly-created TPM object of a subclass of
   * TpmBackEnd.
   */
  public KeyChain(PibImpl pibImpl, TpmBackEnd tpmBackEnd)
    throws PibImpl.Error
  {
    isSecurityV1_ = false;
    policyManager_ = new NoVerifyPolicyManager();

    pib_ = new Pib("", "", pibImpl);
    tpm_ = new Tpm("", "", tpmBackEnd);
  }

  /**
   * Create a new security v1 KeyChain with the given IdentityManager and
   * PolicyManager. For security v2, use KeyChain(pibLocator, tpmLocator) or the
   * default constructor if your .ndn folder is already initialized for v2.
   * @param identityManager An object of a subclass of IdentityManager.
   * @param policyManager An object of a subclass of PolicyManager.
   */
  public KeyChain
    (IdentityManager identityManager, PolicyManager policyManager)
  {
    isSecurityV1_ = true;

    identityManager_ = identityManager;
    policyManager_ = policyManager;
  }

  /**
   * Create a new security v1 KeyChain with the given IdentityManager and a
   * NoVerifyPolicyManager. For security v2, use KeyChain(pibLocator, tpmLocator)
   * or the default constructor if your .ndn folder is already initialized for v2.
   * @param identityManager An object of a subclass of IdentityManager.
   */
  public KeyChain(IdentityManager identityManager)
  {
    isSecurityV1_ = true;

    identityManager_ = identityManager;
    policyManager_ = new NoVerifyPolicyManager();
  }

  /**
   * Create a KeyChain with the default PIB and TPM, which are
   * platform-dependent and can be overridden system-wide or individually by the
   * user. This creates a security v2 KeyChain that uses CertificateV2, Pib, Tpm
   * and Validator. However, if the default security v1 database file still
   * exists, and the default security v2 database file does not yet exists,then
   * assume that the system is running an older NFD and create a security v1
   * KeyChain with the default IdentityManager and a NoVerifyPolicyManager.
   * Note: To create a security v2 KeyChain on android, you must use the
   * KeyChain constructor to provide AndroidSqlite3Pib and TpmBackEndFile
   * objects which are initialized with the explicit directory for the Android
   * filesDir.
   */
  public KeyChain()
    throws SecurityException, KeyChain.Error, PibImpl.Error, IOException
  {
    isSecurityV1_ = false;

    if (BasicIdentityStorage.getDefaultDatabaseFilePath().exists() &&
        !PibSqlite3.getDefaultDatabaseFilePath().exists()) {
      // The security v1 SQLite file still exists and the security v2 does not yet.
      isSecurityV1_ = true;
      identityManager_ = new IdentityManager();
      policyManager_ = new NoVerifyPolicyManager();

      return;
    }

    construct("", "", true);
  }

  public final Pib
  getPib()
  {
    if (isSecurityV1_)
      throw new AssertionError("getPib is not supported for security v1");

    return pib_;
  }

  public final Tpm
  getTpm()
  {
    if (isSecurityV1_)
      throw new AssertionError("getTpm is not supported for security v1");

    return tpm_;
  }

  /**
   * Get the flag set by the constructor if this is a security v1 or v2 KeyChain.
   * @return True if this is a security v1 KeyChain, false if this is a security
   * v2 KeyChain.
   */
  public final boolean
  getIsSecurityV1() { return isSecurityV1_; }

  // Identity management

  /**
   * Create a security V2 identity for identityName. This method will check if
   * the identity exists in PIB and whether the identity has a default key and
   * default certificate. If the identity does not exist, this method will
   * create the identity in PIB. If the identity's default key does not exist,
   * this method will create a key pair and set it as the identity's default
   * key. If the key's default certificate is missing, this method will create a
   * self-signed certificate for the key. If identityName did not exist and no
   * default identity was selected before, the created identity will be set as
   * the default identity.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the
   *   identity.
   * @return The created PibIdentity instance.
   */
  public final PibIdentity
  createIdentityV2(Name identityName, KeyParams params)
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, Error
  {
    PibIdentity id = pib_.addIdentity_(identityName);

    PibKey key;
    try {
      key = id.getDefaultKey();
    }
    catch (Pib.Error ex) {
      key = createKey(id, params);
    }

    try {
      key.getDefaultCertificate();
    }
    catch (Pib.Error ex) {
      Logger.getLogger(this.getClass().getName()).log
        (Level.INFO, "No default cert for " + key.getName() +
         ", requesting self-signing");
      selfSign(key);
    }

    return id;
  }

  /**
   * Create a security V2 identity for identityName. This method will check if
   * the identity exists in PIB and whether the identity has a default key and
   * default certificate. If the identity does not exist, this method will
   * create the identity in PIB. If the identity's default key does not exist,
   * this method will create a key pair using getDefaultKeyParams() and set it
   * as the identity's default key. If the key's default certificate is missing,
   * this method will create a self-signed certificate for the key. If
   * identityName did not exist and no default identity was selected before, the
   * created identity will be set as the default identity.
   * @param identityName The name of the identity.
   * @return The created Identity instance.
   */
  public final PibIdentity
  createIdentityV2(Name identityName)
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, Error
  {
    return createIdentityV2(identityName, getDefaultKeyParams());
  }

  /**
   * Delete the identity. After this operation, the identity is invalid.
   * @param identity The identity to delete.
   */
  public final void
  deleteIdentity(PibIdentity identity) throws PibImpl.Error, TpmBackEnd.Error
  {
    Name identityName = identity.getName();

    ArrayList<Name> keyNames = identity.getKeys_().getKeyNames();
    for (Name keyName : keyNames)
      tpm_.deleteKey_(keyName);

    pib_.removeIdentity_(identityName);
    // TODO: Mark identity as invalid.
  }

  /**
   * Set the identity as the default identity.
   * @param identity The identity to make the default.
   */
  public final void
  setDefaultIdentity(PibIdentity identity) throws PibImpl.Error, Pib.Error
  {
    pib_.setDefaultIdentity_(identity.getName());
  }

  // Key management

  /**
   * Create a key for the identity according to params. If the identity had no
   * default key selected, the created key will be set as the default for this
   * identity. This method will also create a self-signed certificate for the
   * created key.
   * @param identity A valid PibIdentity object.
   * @param params The key parameters if a key needs to be generated for the
   * identity.
   * @return The new PibKey.
   */
  public final PibKey
  createKey(PibIdentity identity, KeyParams params)
    throws Tpm.Error, TpmBackEnd.Error, PibImpl.Error, Pib.Error, KeyChain.Error
  {
    // Create the key in the TPM.
    Name keyName = tpm_.createKey_(identity.getName(), params);

    // Set up the key info in the PIB.
    Blob publicKey = tpm_.getPublicKey(keyName);
    PibKey key = identity.addKey_(publicKey.buf(), keyName);

    Logger.getLogger(this.getClass().getName()).log
      (Level.INFO,
       "Requesting self-signing for newly created key " + key.getName().toUri());
    selfSign(key);

    return key;
  }

  /**
   * Create a key for the identity according to getDefaultKeyParams(). If the
   * identity had no default key selected, the created key will be set as the
   * default for this identity. This method will also create a self-signed
   * certificate for the created key.
   * @param identity A valid PibIdentity object.
   * @return The new PibKey.
   */
  public final PibKey
  createKey(PibIdentity identity)
    throws Tpm.Error, TpmBackEnd.Error, PibImpl.Error, Pib.Error, KeyChain.Error
  {
    return createKey(identity, getDefaultKeyParams());
  }

  /**
   * Delete the given key of the given identity. The key becomes invalid.
   * @param identity A valid PibIdentity object.
   * @param key The key to delete.
   * @throws IllegalArgumentException If the key does not belong to the identity.
   */
  public final void
  deleteKey(PibIdentity identity, PibKey key)
    throws PibImpl.Error, TpmBackEnd.Error
  {
    Name keyName = key.getName();
    if (!identity.getName().equals(key.getIdentityName()))
      throw new IllegalArgumentException("Identity `" +
        identity.getName().toUri() + "` does not match key `" +
        keyName.toUri() + "`");

    identity.removeKey_(keyName);
    tpm_.deleteKey_(keyName);
  }

  /**
   * Set the key as the default key of identity.
   * @param identity A valid PibIdentity object.
   * @param key The key to become the default.
   * @throws IllegalArgumentException If the key does not belong to the identity.
   */
  public final void
  setDefaultKey(PibIdentity identity, PibKey key) throws Pib.Error, PibImpl.Error
  {
    if (!identity.getName().equals(key.getIdentityName()))
      throw new IllegalArgumentException("Identity `" + identity.getName().toUri() +
        "` does not match key `" + key.getName().toUri() + "`");

    identity.setDefaultKey_(key.getName());
  }

  // Certificate management

  /**
   * Add a certificate for the key. If the key had no default certificate
   * selected, the added certificate will be set as the default certificate for
   * this key.
   * @param key A valid PibKey object.
   * @param certificate The certificate to add. This copies the object.
   * @note This method overwrites a certificate with the same name, without
   * considering the implicit digest.
   * @throws IllegalArgumentException If the key does not match the certificate.
   */
  public final void
  addCertificate(PibKey key, CertificateV2 certificate)
    throws CertificateV2.Error, PibImpl.Error
  {
    if (!key.getName().equals(certificate.getKeyName()) ||
        !certificate.getContent().equals(key.getPublicKey()))
      throw new IllegalArgumentException("Key `" + key.getName().toUri() +
        "` does not match certificate `" + certificate.getKeyName().toUri() + "`");

    key.addCertificate_(certificate);
  }

  /**
   * Delete the certificate with the given name from the given key.
   * If the certificate does not exist, this does nothing.
   * @param key A valid PibKey object.
   * @param certificateName The name of the certificate to delete.
   * @throws IllegalArgumentException If certificateName does not follow
   * certificate naming conventions.
   */
  public final void
  deleteCertificate(PibKey key, Name certificateName) throws PibImpl.Error
  {
    if (!CertificateV2.isValidName(certificateName))
      throw new IllegalArgumentException("Wrong certificate name `" +
        certificateName.toUri() + "`");

    key.removeCertificate_(certificateName);
  }

  /**
   * Set the certificate as the default certificate of the key. The certificate
   * will be added to the key, potentially overriding an existing certificate if
   * it has the same name (without considering implicit digest).
   * @param key A valid PibKey object.
   * @param certificate The certificate to become the default. This copies the
   * object.
   */
  public final void
  setDefaultCertificate(PibKey key, CertificateV2 certificate)
    throws PibImpl.Error, CertificateV2.Error, Pib.Error
  {
    // This replaces the certificate it it exists.
    addCertificate(key, certificate);
    key.setDefaultCertificate_(certificate.getName());
  }

  // Signing

  /**
   * Wire encode the Data object, sign it according to the supplied signing
   * parameters, and set its signature.
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key and other info in the SigningInfo params,
   * and updates the wireEncoding.
   * @param params The signing parameters.
   * @param wireFormat A WireFormat object used to encode the input.
   * @throws KeyChain.Error if signing fails.
   * @throws KeyChain.InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  public final void
  sign(Data data, SigningInfo params, WireFormat wireFormat)
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    Name[] keyName = new Name[1];
    Signature signatureInfo = prepareSignatureInfo(params, keyName);

    data.setSignature(signatureInfo);

    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);

    Blob signatureBytes = sign
      (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm());
    data.getSignature().setSignature(signatureBytes);

    // Encode again to include the signature.
    data.wireEncode(wireFormat);
  }

  /**
   * Wire encode the Data object, sign it according to the supplied signing
   * parameters, and set its signature.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key and other info in the SigningInfo params,
   * and updates the wireEncoding.
   * @param params The signing parameters.
   * @throws KeyChain.Error if signing fails.
   * @throws KeyChain.InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  public final void
  sign(Data data, SigningInfo params)
    throws TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    sign(data, params, WireFormat.getDefaultWireFormat());
  }

  /**
   * Wire encode the Data object, sign it with the default key of the default
   * identity, and set its signature.
   * If this is a security v1 KeyChain then use the IdentityManager to get the
   * default identity. Otherwise use the PIB.
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key of the default identity, and updates the
   * wireEncoding.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public final void
  sign(Data data, WireFormat wireFormat)
    throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    if (isSecurityV1_) {
      identityManager_.signByCertificate
        (data, prepareDefaultCertificateName(), wireFormat);
      return;
    }

    sign(data, defaultSigningInfo_, wireFormat);
  }

  /**
   * Wire encode the Data object, sign it with the default key of the default
   * identity, and set its signature.
   * If this is a security v1 KeyChain then use the IdentityManager to get the
   * default identity. Otherwise use the PIB.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key of the default identity, and updates the
   * wireEncoding.
   */
  public final void
  sign(Data data)
    throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    sign(data, WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the Interest according to the supplied signing parameters. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param params The signing parameters.
   * @param wireFormat A WireFormat object used to encode the input and encode
   * the appended components.
   * @throws KeyChain.Error if signing fails.
   * @throws KeyChain.InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  public final void
  sign(Interest interest, SigningInfo params, WireFormat wireFormat)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Name[] keyName = new Name[1];
    Signature signatureInfo = prepareSignatureInfo(params, keyName);

    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signatureInfo));

    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());
    // Encode once to get the signed portion, and sign.
    SignedBlob encoding = interest.wireEncode(wireFormat);
    Blob signatureBytes = sign
      (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm());
    signatureInfo.setSignature(signatureBytes);

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signatureInfo)));
  }

  /**
   * Sign the Interest according to the supplied signing parameters. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param params The signing parameters.
   * @throws KeyChain.Error if signing fails.
   * @throws KeyChain.InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  public final void
  sign(Interest interest, SigningInfo params)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    sign(interest, params, WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the Interest with the default key of the default identity. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * If this is a security v1 KeyChain then use the IdentityManager to get the
   * default identity. Otherwise use the PIB.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param wireFormat A WireFormat object used to encode the input and encode
   * the appended components.
   */
  public final void
  sign(Interest interest, WireFormat wireFormat)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error, SecurityException
  {
    if (isSecurityV1_) {
      identityManager_.signInterestByCertificate
        (interest, prepareDefaultCertificateName(), wireFormat);
      return;
    }

    sign(interest, defaultSigningInfo_, wireFormat);
  }

  /**
   * Sign the Interest with the default key of the default identity. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * Use the default WireFormat.getDefaultWireFormat().
   * If this is a security v1 KeyChain then use the IdentityManager to get the
   * default identity. Otherwise use the PIB.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   */
  public final void
  sign(Interest interest)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error, SecurityException
  {
    sign(interest, WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the byte buffer according to the supplied signing parameters.
   * @param buffer The byte buffer to be signed.
   * @param params The signing parameters. If params refers to an identity, this
   * selects the default key of the identity. If params refers to a key or
   * certificate, this selects the corresponding key.
   * @return The signature Blob, or an isNull Blob if params.getDigestAlgorithm()
   * is unrecognized.
   */
  public final Blob
  sign(ByteBuffer buffer, SigningInfo params)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    Name[] keyName = new Name[1];
    Signature signatureInfo = prepareSignatureInfo(params, keyName);

    return sign(buffer, keyName[0], params.getDigestAlgorithm());
  }

  /**
   * Sign the byte buffer using the default key of the default identity.
   * @param buffer The byte buffer to be signed.
   * @return The signature Blob.
   */
  public final Blob
  sign(ByteBuffer buffer)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    return sign(buffer, defaultSigningInfo_);
  }

  /**
   * Generate a self-signed certificate for the public key and add it to the
   * PIB. This creates the certificate name from the key name by appending
   * "self" and a version based on the current time. If no default certificate
   * for the key has been set, then set the certificate as the default for the
   * key.
   * @param key The PibKey with the key name and public key.
   * @param wireFormat A WireFormat object used to encode the certificate.
   * @return The new certificate.
   */
  public final CertificateV2
  selfSign(PibKey key, WireFormat wireFormat)
    throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    CertificateV2 certificate = new CertificateV2();

    // Set the name.
    double now = Common.getNowMilliseconds();
    Name certificateName = new Name(key.getName());
    certificateName.append("self").appendVersion((long)now);
    certificate.setName(certificateName);

    // Set the MetaInfo.
    certificate.getMetaInfo().setType(ContentType.KEY);
    // Set a one-hour freshness period.
    certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

    // Set the content.
    certificate.setContent(key.getPublicKey());

    // Set the signature-info.
    SigningInfo signingInfo = new SigningInfo(key);
    // Set a 20-year validity period.
    signingInfo.setValidityPeriod
      (new ValidityPeriod(now, now + 20 * 365 * 24 * 3600 * 1000.0));

    sign(certificate, signingInfo, wireFormat);

    try {
      key.addCertificate_(certificate);
    } catch (CertificateV2.Error ex) {
      // We don't expect this since we just created the certificate.
      throw new Error("Error encoding certificate: " + ex);
    }
    return certificate;
  }


  /**
   * Generate a self-signed certificate for the public key and add it to the
   * PIB. This creates the certificate name from the key name by appending
   * "self" and a version based on the current time. If no default certificate
   * for the key has been set, then set the certificate as the default for the
   * key.
   * Use the default WireFormat.getDefaultWireFormat() to encode the certificate.
   * @param key The PibKey with the key name and public key.
   * @return The new certificate.
   */
  public final CertificateV2
  selfSign(PibKey key) throws PibImpl.Error, KeyChain.Error, TpmBackEnd.Error
  {
    return selfSign(key, WireFormat.getDefaultWireFormat());
  }

  // Import and export

  /**
   * Export a certificate and its corresponding private key in a SafeBag.
   * @param certificate The certificate to export. This gets the key from the
   * TPM using certificate.getKeyName().
   * @param password The password for encrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to put a PKCS #8 EncryptedPrivateKeyInfo in the SafeBag. If the password
   * is null, put an unencrypted PKCS #8 PrivateKeyInfo in the SafeBag.
   * @return A SafeBag carrying the certificate and private key.
   * @throws KeyChain.Error certificate.getKeyName() key does not exist, if the
   * password is null and the TPM does not support exporting an unencrypted
   * private key, or for other errors exporting the private key.
   */
  public final SafeBag
  exportSafeBag(CertificateV2 certificate, ByteBuffer password)
    throws KeyChain.Error
  {
    Name keyName = certificate.getKeyName();

    Blob encryptedKey;
    try {
      encryptedKey = tpm_.exportPrivateKey_(keyName, password);
    } catch (Throwable ex) {
      throw new KeyChain.Error("Failed to export private key `" +
        keyName.toUri() + "`: " + ex);
    }

    return new SafeBag(certificate, encryptedKey);
  }

  /**
   * Export a certificate and its corresponding private key in a SafeBag, with a
   * null password which exports an unencrypted PKCS #8 PrivateKeyInfo.
   * @param certificate The certificate to export. This gets the key from the
   * TPM using certificate.getKeyName().
   * @return A SafeBag carrying the certificate and private key.
   * @throws KeyChain.Error certificate.getKeyName() key does not exist, if the
   * TPM does not support exporting an unencrypted private key, or for other
   * errors exporting the private key.
   */
  public final SafeBag
  exportSafeBag(CertificateV2 certificate)
    throws KeyChain.Error
  {
    return exportSafeBag(certificate, null);
  }

  /**
   * Import a certificate and its corresponding private key encapsulated in a
   * SafeBag. If the certificate and key are imported properly, the default
   * setting will be updated as if a new key and certificate is added into this
   * KeyChain.
   * @param safeBag The SafeBag containing the certificate and private key. This
   * copies the values from the SafeBag.
   * @param password The password for decrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * import an unencrypted PKCS #8 PrivateKeyInfo.
   * @throws KeyChain.Error if the private key cannot be imported, or if a
   * public key or private key of the same name already exists, or if a
   * certificate of the same name already exists.
   */
  public final void
  importSafeBag(SafeBag safeBag, ByteBuffer password)
    throws KeyChain.Error, CertificateV2.Error, TpmBackEnd.Error, PibImpl.Error,
      Pib.Error
  {
    CertificateV2 certificate = new CertificateV2(safeBag.getCertificate());
    Name identity = certificate.getIdentity();
    Name keyName = certificate.getKeyName();
    Blob publicKeyBits = certificate.getPublicKey();

    if (tpm_.hasKey(keyName))
      throw new KeyChain.Error("Private key `" + keyName.toUri() +
        "` already exists");

    try {
      PibIdentity existingId = pib_.getIdentity(identity);
      existingId.getKey(keyName);
      throw new KeyChain.Error("Public key `" + keyName.toUri() +
        "` already exists");
    } catch (Pib.Error ex) {
      // Either the identity or the key doesn't exist, so OK to import.
    }

    try {
      tpm_.importPrivateKey_(keyName, safeBag.getPrivateKeyBag().buf(), password);
    } catch (Exception ex) {
      throw new KeyChain.Error("Failed to import private key `" +
        keyName.toUri() + "`: " + ex);
    }

    // Check the consistency of the private key and certificate.
    Blob content = new Blob(new int[] {0x01, 0x02, 0x03, 0x04});
    Blob signatureBits;
    try {
      signatureBits = tpm_.sign(content.buf(), keyName, DigestAlgorithm.SHA256);
    } catch (Exception ex) {
      tpm_.deleteKey_(keyName);
      throw new KeyChain.Error("Invalid private key `" + keyName.toUri() + "`");
    }

    PublicKey publicKey;
    try {
      publicKey = new PublicKey(publicKeyBits);
    } catch (UnrecognizedKeyFormatException ex) {
      // Promote to KeyChain.Error.
      tpm_.deleteKey_(keyName);
      throw new KeyChain.Error("Error decoding public key " + ex);
    }

    if (!VerificationHelpers.verifySignature(content, signatureBits, publicKey)) {
      tpm_.deleteKey_(keyName);
      throw new KeyChain.Error("Certificate `" + certificate.getName().toUri() +
        "` and private key `" + keyName.toUri() + "` do not match");
    }

    // The consistency is verified. Add to the PIB.
    PibIdentity id = pib_.addIdentity_(identity);
    PibKey key = id.addKey_(certificate.getPublicKey().buf(), keyName);
    key.addCertificate_(certificate);
  }

  /**
   * Import a certificate and its corresponding private key encapsulated in a
   * SafeBag, with a null password which imports an unencrypted PKCS #8
   * PrivateKeyInfo. If the certificate and key are imported properly, the
   * default setting will be updated as if a new key and certificate is added
   * into this KeyChain.
   * @param safeBag The SafeBag containing the certificate and private key. This
   * copies the values from the SafeBag.
   * @throws KeyChain.Error if the private key cannot be imported, or if a
   * public key or private key of the same name already exists, or if a
   * certificate of the same name already exists.
   */
  public final void
  importSafeBag(SafeBag safeBag)
    throws KeyChain.Error, CertificateV2.Error, TpmBackEnd.Error, PibImpl.Error,
      Pib.Error
  {
    importSafeBag(safeBag, null);
  }

  // PIB & TPM backend registry

  /**
   * Add to the PIB factories map where scheme is the key and makePibImpl is the
   * value. If your application has its own PIB implementations, this must be
   * called before creating a KeyChain instance which uses your PIB scheme.
   * @param scheme The PIB scheme.
   * @param makePibImpl An interface with makePibImpl which takes the PIB
   * location and returns a new PibImpl instance.
   */
  public static void
  registerPibBackend(String scheme, MakePibImpl makePibImpl)
  {
    getPibFactories().put(scheme, makePibImpl);
  }

  /**
   * Add to the TPM factories map where scheme is the key and makeTpmBackEnd is
   * the value. If your application has its own TPM implementations, this must
   * be called before creating a KeyChain instance which uses your TPM scheme.
   * @param scheme The TPM scheme.
   * @param makeTpmBackEnd An interface with makeTpmBackEnd which takes the TPM
   * location and returns a new TpmBackEnd instance.
   */
  public static void
  registerTpmBackend(String scheme, MakeTpmBackEnd makeTpmBackEnd)
  {
    getTpmFactories().put(scheme, makeTpmBackEnd);
  }

  // Security v1 methods

  /*****************************************
   *          Identity Management          *
   *****************************************/

  /**
   * Create a security v1 identity by creating a pair of Key-Signing-Key (KSK)
   * for this identity and a self-signed certificate of the KSK. If a key pair or
   * certificate for the identity already exists, use it.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the
   * identity.
   * @return The name of the default certificate of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public final Name
  createIdentityAndCertificate(Name identityName, KeyParams params)
    throws SecurityException
  {
    return identityManager_.createIdentityAndCertificate(identityName, params);
  }

  /**
   * Create a security v1 identity by creating a pair of Key-Signing-Key (KSK)
   * for this identity and a self-signed certificate of the KSK. Use
   * getDefaultKeyParams() to create the key if needed. If a key pair or
   * certificate for the identity already exists, use it.
   * @param identityName The name of the identity.
   * @return The name of the default certificate of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public final Name
  createIdentityAndCertificate(Name identityName) throws SecurityException
  {
    return createIdentityAndCertificate(identityName, getDefaultKeyParams());
  }

  /**
   * Create a security v1 identity by creating a pair of Key-Signing-Key (KSK)
   * for this identity and a self-signed certificate of the KSK.
   * @deprecated Use createIdentityAndCertificate which returns the
   * certificate name instead of the key name.
   * @param identityName The name of the identity.
   * @param params The key parameters if a key needs to be generated for the
   * identity.
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
   * Create a security v1 identity by creating a pair of Key-Signing-Key (KSK)
   * for this identity and a self-signed certificate of the KSK. Use
   * getDefaultKeyParams() to create the key if needed.
   * @deprecated Use createIdentityAndCertificate which returns the
   * certificate name instead of the key name.
   * @param identityName The name of the identity.
   * @return The key name of the auto-generated KSK of the identity.
   * @throws SecurityException if the identity has already been created.
   */
  public final Name
  createIdentity(Name identityName) throws SecurityException
  {
    return IdentityCertificate.certificateNameToPublicKeyName
      (createIdentityAndCertificate(identityName));
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
    if (!isSecurityV1_) {
      try {
        deleteIdentity(pib_.getIdentity(identityName));
      } catch (Pib.Error ex) {
      } catch (PibImpl.Error ex) {
      } catch (TpmBackEnd.Error ex) {
      }
      return;
    }

    identityManager_.deleteIdentity(identityName);
  }

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public final Name
  getDefaultIdentity() throws SecurityException
  {
    if (!isSecurityV1_) {
      try {
        return pib_.getDefaultIdentity().getName();
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in getDefaultIdentity: " + ex);
      } catch (Pib.Error ex) {
        throw new SecurityException("Error in getDefaultIdentity: " + ex);
      }
    }

    return identityManager_.getDefaultIdentity();
  }

  /**
   * Get the default certificate name of the default identity.
   * @return The requested certificate name.
   * @throws SecurityException if the default identity is not set or the default
   * key name for the identity is not set or the default certificate name for
   * the key name is not set.
   */
  public final Name
  getDefaultCertificateName() throws SecurityException
  {
    if (!isSecurityV1_) {
      try {
        return pib_.getDefaultIdentity().getDefaultKey().getDefaultCertificate()
                .getName();
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in getDefaultCertificate: " + ex);
      } catch (Pib.Error ex) {
        throw new SecurityException("Error in getDefaultCertificate: " + ex);
      }
    }

    return identityManager_.getDefaultCertificateName();
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPair(identityName, isKsk, keySize);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPair(identityName, isKsk);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPair(identityName);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPair(identityName, isKsk, keySize);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPair(identityName, isKsk);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPair is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPair(identityName);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("setDefaultKeyForIdentity is not supported for security v2. Use getPib() methods.");

    identityManager_.setDefaultKeyForIdentity(keyName, identityNameCheck);
  }

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   */
  public final void
  setDefaultKeyForIdentity(Name keyName) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("setDefaultKeyForIdentity is not supported for security v2. Use getPib() methods.");

    identityManager_.setDefaultKeyForIdentity(keyName);
  }

  /**
   * Generate a pair of RSA keys for the specified identity and set it as the
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPairAsDefault(identityName, isKsk, keySize);
  }

  /**
   * Generate a pair of RSA keys for the specified identity and set it as the
   * default key for the identity, using the default keySize 2048.
   * @param identityName The name of the identity.
   * @param isKsk true for generating a Key-Signing-Key (KSK), false for a Data-Signing-Key (KSK).
   * @return The generated key name.
   */
  public final Name
  generateRSAKeyPairAsDefault(Name identityName, boolean isKsk) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPairAsDefault(identityName, isKsk);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateRSAKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateRSAKeyPairAsDefault(identityName);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPairAsDefault(identityName, isKsk, keySize);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPairAsDefault(identityName, isKsk);
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
    if (!isSecurityV1_)
      throw new SecurityException
        ("generateEcdsaKeyPairAsDefault is not supported for security v2. Use createIdentityV2.");

    return identityManager_.generateEcdsaKeyPairAsDefault(identityName);
  }

  /**
   * Create a public key signing request.
   * @param keyName The name of the key.
   * @return The signing request data.
   * @throws SecurityException if the keyName is not found.
   */
  public final Blob
  createSigningRequest(Name keyName) throws SecurityException
  {
    if (!isSecurityV1_) {
      try {
        return pib_.getIdentity(PibKey.extractIdentityFromKeyName(keyName))
                .getKey(keyName).getPublicKey();
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in getKey: " + ex);
      } catch (Pib.Error ex) {
        throw new SecurityException("Error in getKey: " + ex);
      }
    }

    return identityManager_.getPublicKey(keyName).getKeyDer();
  }

  /**
   * Install an identity certificate into the public key identity storage.
   * @param certificate The certificate to to added.
   */
  public final void
  installIdentityCertificate(IdentityCertificate certificate) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("installIdentityCertificate is not supported for security v2. Use getPib() methods.");

    identityManager_.addCertificate(certificate);
  }

  /**
   * Set the certificate as the default for its corresponding key.
   * @param certificate The certificate.
   */
  public final void
  setDefaultCertificateForKey(IdentityCertificate certificate) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("setDefaultCertificateForKey is not supported for security v2. Use getPib() methods.");

    identityManager_.setDefaultCertificateForKey(certificate);
  }

  /**
   * Get a certificate with the specified name.
   * @param certificateName The name of the requested certificate.
   * @return The requested certificate.
   */
  public final IdentityCertificate
  getCertificate(Name certificateName) throws SecurityException, DerDecodingException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("getCertificate is not supported for security v2. Use getPib() methods.");

    return identityManager_.getCertificate(certificateName);
  }

  /**
   * @deprecated Use getCertificate.
   */
  public final IdentityCertificate
  getIdentityCertificate(Name certificateName) throws SecurityException, DerDecodingException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("getIdentityCertificate is not supported for security v2. Use getPib() methods.");

    return identityManager_.getCertificate(certificateName);
  }

  /**
   * Revoke a key.
   * @param keyName The name of the key that will be revoked.
   */
  public final void
  revokeKey(Name keyName)
  {
    //TODO: Implement
  }

  /**
   * Revoke a certificate.
   * @param certificateName The name of the certificate that will be revoked.
   */
  public final void
  revokeCertificate(Name certificateName)
  {
    //TODO: Implement
  }

  /**
   * Get the identity manager given to or created by the constructor.
   * @return The identity manager.
   */
  public final IdentityManager
  getIdentityManager()
  {
    if (!isSecurityV1_)
      throw new AssertionError
        ("getIdentityManager is not supported for security v2");

    return identityManager_;
  }


  /*****************************************
   *              Sign/Verify              *
   *****************************************/

  /**
   * Wire encode the Data object, sign it and set its signature.
   * @param data The Data object to be signed.  This updates its signature and
   * key locator field and wireEncoding.
   * @param certificateName The certificate name of the key to use for signing.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public final void
  sign(Data data, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    if (!isSecurityV1_) {
      SigningInfo signingInfo = new SigningInfo();
      signingInfo.setSigningCertificateName(certificateName);
      try {
        sign(data, signingInfo, wireFormat);
      } catch (TpmBackEnd.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      }
      return;
    }

    identityManager_.signByCertificate(data, certificateName, wireFormat);
  }

  /**
   * Wire encode the Data object, sign it and set its signature.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param data The Data object to be signed.  This updates its signature and
   * key locator field and wireEncoding.
   * @param certificateName The certificate name of the key to use for signing.
   */
  public final void
  sign(Data data, Name certificateName) throws SecurityException
  {
    sign(data, certificateName, WireFormat.getDefaultWireFormat());
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
  sign(Interest interest, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    if (!isSecurityV1_) {
      SigningInfo signingInfo = new SigningInfo();
      signingInfo.setSigningCertificateName(certificateName);
      try {
        sign(interest, signingInfo, wireFormat);
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (TpmBackEnd.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      }
      return;
    }

    identityManager_.signInterestByCertificate
      (interest, certificateName, wireFormat);
  }

  /**
   * Append a SignatureInfo to the Interest name, sign the name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param certificateName The certificate name of the key to use for signing.
   */
  public final void
  sign(Interest interest, Name certificateName) throws SecurityException
  {
    sign(interest, certificateName, WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the byte buffer using a certificate name and return a Signature object.
   * @param buffer The byte array to be signed.
   * @param certificateName The certificate name used to get the signing key and which will be put into KeyLocator.
   * @return The Signature.
   */
  public Signature
  sign(ByteBuffer buffer, Name certificateName) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("sign(buffer, certificateName) is not supported for security v2. Use sign with SigningInfo.");

    return identityManager_.signByCertificate(buffer, certificateName);
  }

  /**
   * Wire encode the Data object, sign it and set its signature.
   * @param data The Data object to be signed.  This updates its signature and
   * key locator field and wireEncoding.
   * @param identityName The identity name for the key to use for signing.
   * If empty, infer the signing identity from the data packet name.
   * @param wireFormat A WireFormat object used to encode the input. If omitted, use WireFormat getDefaultWireFormat().
   */
  public final void
  signByIdentity
    (Data data, Name identityName, WireFormat wireFormat) throws SecurityException
  {
    if (!isSecurityV1_) {
      SigningInfo signingInfo = new SigningInfo();
      signingInfo.setSigningIdentity(identityName);
      try {
        sign(data, signingInfo, wireFormat);
      } catch (TpmBackEnd.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      }
      return;
    }

    Name signingCertificateName;

    if (identityName.size() == 0) {
      Name inferredIdentity = policyManager_.inferSigningIdentity(data.getName());
      if (inferredIdentity.size() == 0)
        signingCertificateName = identityManager_.getDefaultCertificateName();
      else
        signingCertificateName =
          identityManager_.getDefaultCertificateNameForIdentity(inferredIdentity);
    }
    else
      signingCertificateName =
        identityManager_.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException("No qualified certificate name found!");

    if (!policyManager_.checkSigningPolicy(data.getName(), signingCertificateName))
      throw new SecurityException
        ("Signing Cert name does not comply with signing policy");

    identityManager_.signByCertificate(data, signingCertificateName, wireFormat);
  }

  /**
   * Wire encode the Data object, sign it and set its signature.
   * @param data The Data object to be signed.  This updates its signature and
   * key locator field and wireEncoding.
   * Use the default WireFormat.getDefaultWireFormat().
   * @param identityName The identity name for the key to use for signing.
   * If empty, infer the signing identity from the data packet name.
   */
  public final void
  signByIdentity(Data data, Name identityName) throws SecurityException
  {
    signByIdentity(data, identityName, WireFormat.getDefaultWireFormat());
  }

  /**
   * Wire encode the Data object, sign it and set its signature.
   * @param data The Data object to be signed.  This updates its signature and
   * key locator field and wireEncoding.
   * Infer the signing identity from the data packet name.
   * Use the default WireFormat.getDefaultWireFormat().
   */
  public final void
  signByIdentity(Data data) throws SecurityException
  {
    signByIdentity(data, new Name(), WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the byte buffer using an identity name and return a Signature object.
   * @param buffer The byte array to be signed.
   * @param identityName The identity name.
   * @return The Signature.
   */
  public Signature
  signByIdentity(ByteBuffer buffer, Name identityName) throws SecurityException
  {
    if (!isSecurityV1_)
      throw new SecurityException
        ("signByIdentity(buffer, identityName) is not supported for security v2. Use sign with SigningInfo.");

    Name signingCertificateName =
      identityManager_.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException("No qualified certificate name found!");

    return identityManager_.signByCertificate(buffer, signingCertificateName);
  }

  /**
   * Wire encode the Data object, digest it and set its SignatureInfo to
   * a DigestSha256.
   * @param data The Data object to be signed. This updates its signature and
   * wireEncoding.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public final void
  signWithSha256(Data data, WireFormat wireFormat) throws SecurityException
  {
    if (!isSecurityV1_) {
      SigningInfo signingInfo = new SigningInfo();
      signingInfo.setSha256Signing();
      try {
        sign(data, signingInfo, wireFormat);
      } catch (TpmBackEnd.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      }
      return;
    }

    identityManager_.signWithSha256(data, wireFormat);
  }

  /**
   * Wire encode the Data object, digest it and set its SignatureInfo to
   * a DigestSha256.
   * @param data The Data object to be signed. This updates its signature and
   * wireEncoding.
   */
  public final void
  signWithSha256(Data data) throws SecurityException
  {
    signWithSha256(data, WireFormat.getDefaultWireFormat());
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
  signWithSha256(Interest interest, WireFormat wireFormat) throws SecurityException
  {
    if (!isSecurityV1_) {
      SigningInfo signingInfo = new SigningInfo();
      signingInfo.setSha256Signing();
      try {
        sign(interest, signingInfo, wireFormat);
      } catch (PibImpl.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      } catch (TpmBackEnd.Error ex) {
        throw new SecurityException("Error in sign: " + ex);
      }
      return;
    }

    identityManager_.signInterestWithSha256(interest, wireFormat);
  }

  /**
   * Append a SignatureInfo for DigestSha256 to the Interest name, digest the
   * name components and append a final name component with the signature bits
   * (which is the digest).
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   */
  public final void
  signWithSha256(Interest interest) throws SecurityException
  {
    signWithSha256(interest, WireFormat.getDefaultWireFormat());
  }

  public final void
  verifyData
    (Data data, OnVerified onVerified, OnDataValidationFailed onValidationFailed,
     int stepCount) throws SecurityException
  {
    Logger.getLogger(this.getClass().getName()).log
      (Level.INFO, "Enter Verify");

    if (policyManager_.requireVerify(data)) {
      ValidationRequest nextStep = policyManager_.checkVerificationPolicy
        (data, stepCount, onVerified, onValidationFailed);
      if (nextStep != null) {
        VerifyCallbacks callbacks = new VerifyCallbacks
          (nextStep, nextStep.retry_, onValidationFailed, data);
        try {
          face_.expressInterest(nextStep.interest_, callbacks, callbacks);
        }
        catch (IOException ex) {
          try {
            onValidationFailed.onDataValidationFailed
              (data, "Error calling expressInterest " + ex);
          } catch (Throwable exception) {
            logger_.log(Level.SEVERE, "Error in onDataValidationFailed", exception);
          }
        }
      }
    }
    else if (policyManager_.skipVerifyAndTrust(data)) {
      try {
        onVerified.onVerified(data);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerified", ex);
      }
    }
    else {
      try {
        onValidationFailed.onDataValidationFailed
          (data,
           "The packet has no verify rule but skipVerifyAndTrust is false");
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onDataValidationFailed", ex);
      }
    }
  }

  /**
   * Check the signature on the Data object and call either onVerify.onVerify or
   * onValidationFailed.onDataValidationFailed.
   * We use callback functions because verify may fetch information to check the
   * signature.
   * @param data The Data object with the signature to check. It is an error if
   * data does not have a wireEncoding.
   * To set the wireEncoding, you can call data.wireDecode.
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed If the signature check fails, this calls
   * onValidationFailed.onDataValidationFailed(data, reason).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  verifyData
    (Data data, OnVerified onVerified, OnDataValidationFailed onValidationFailed)
    throws SecurityException
  {
    verifyData(data, onVerified, onValidationFailed, 0);
  }

  /**
   * Check the signature on the Data object and call either onVerify.onVerify or
   * onVerifyFailed.onVerifyFailed.
   * We use callback functions because verify may fetch information to check the
   * signature.
   * @deprecated Use verifyData with OnDataValidationFailed.
   * @param data The Data object with the signature to check. It is an error if
   * data does not have a wireEncoding.
   * To set the wireEncoding, you can call data.wireDecode.
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onVerifyFailed If the signature check fails, this calls
   * onVerifyFailed.onVerifyFailed(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  verifyData
    (Data data, OnVerified onVerified, final OnVerifyFailed onVerifyFailed)
    throws SecurityException
  {
    // Wrap the onVerifyFailed in an OnDataValidationFailed.
    verifyData
      (data, onVerified,
       new OnDataValidationFailed() {
         public void onDataValidationFailed(Data localData, String reason) {
           onVerifyFailed.onVerifyFailed(localData);
         }
       });
  }

  public final void
  verifyInterest
    (Interest interest, OnVerifiedInterest onVerified,
     OnInterestValidationFailed onValidationFailed, int stepCount)
    throws SecurityException
  {
    Logger.getLogger(this.getClass().getName()).log
      (Level.INFO, "Enter Verify");

    if (policyManager_.requireVerify(interest)) {
      ValidationRequest nextStep = policyManager_.checkVerificationPolicy
        (interest, stepCount, onVerified, onValidationFailed);
      if (nextStep != null) {
        VerifyCallbacksForVerifyInterest callbacks = new VerifyCallbacksForVerifyInterest
          (nextStep, nextStep.retry_, onValidationFailed, interest);
        try {
          face_.expressInterest(nextStep.interest_, callbacks, callbacks);
        }
        catch (IOException ex) {
          try {
            onValidationFailed.onInterestValidationFailed
              (interest, "Error calling expressInterest " + ex);
          } catch (Throwable exception) {
            logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", exception);
          }
        }
      }
    }
    else if (policyManager_.skipVerifyAndTrust(interest)) {
      try {
        onVerified.onVerifiedInterest(interest);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerifiedInterest", ex);
      }
    }
    else {
      try {
        onValidationFailed.onInterestValidationFailed
          (interest,
           "The packet has no verify rule but skipVerifyAndTrust is false");
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", ex);
      }
    }
  }

  /**
   * Check the signature on the signed interest and call either
   * onVerify.onVerifiedInterest or
   * onValidationFailed.onInterestValidationFailed. We
   * use callback functions because verify may fetch information to check the
   * signature.
   * @param interest The interest with the signature to check.
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerifiedInterest(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed If the signature check fails, this calls
   * onValidationFailed.onInterestValidationFailed(interest, reason).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  verifyInterest
    (Interest interest, OnVerifiedInterest onVerified,
     OnInterestValidationFailed onValidationFailed) throws SecurityException
  {
    verifyInterest(interest, onVerified, onValidationFailed, 0);
  }

  /**
   * Check the signature on the signed interest and call either
   * onVerify.onVerifiedInterest or onVerifyFailed.onVerifyInterestFailed. We
   * use callback functions because verify may fetch information to check the
   * signature.
   * @deprecated Use verifyInterest with OnInterestValidationFailed.
   * @param interest The interest with the signature to check.
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerifiedInterest(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onVerifyFailed If the signature check fails, this calls
   * onVerifyFailed.onVerifyInterestFailed(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  verifyInterest
    (Interest interest, OnVerifiedInterest onVerified,
     final OnVerifyInterestFailed onVerifyFailed) throws SecurityException
  {
    // Wrap the onVerifyFailed in an OnInterestValidationFailed.
    verifyInterest
      (interest, onVerified,
       new OnInterestValidationFailed() {
         public void onInterestValidationFailed
           (Interest localInterest, String reason) {
           onVerifyFailed.onVerifyInterestFailed(localInterest);
         }
       });
  }

  /**
   * Set the Face which will be used to fetch required certificates.
   * @param face The Face object.
   */
  public final void
  setFace(Face face) { face_ = face; }

  /**
   * Wire encode the data packet, compute an HmacWithSha256 and update the
   * signature value.
   * @note This method is an experimental feature. The API may change.
   * @param data The Data object to be signed. This updates its signature.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat A WireFormat object used to encode the data packet.
   */
  public static void
  signWithHmacWithSha256(Data data, Blob key, WireFormat wireFormat)
  {
    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);
    byte[] signatureBytes = Common.computeHmacWithSha256
      (key.getImmutableArray(), encoding.signedBuf());
    data.getSignature().setSignature(new Blob(signatureBytes, false));
  }

  /**
   * Wire encode the data packet, compute an HmacWithSha256 and update the
   * signature value.
   * Use the default WireFormat.getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   * @param data The Data object to be signed. This updates its signature.
   * @param key The key for the HmacWithSha256.
   */
  public static void
  signWithHmacWithSha256(Data data, Blob key)
  {
    signWithHmacWithSha256(data, key, WireFormat.getDefaultWireFormat());
  }

  /**
   * Append a SignatureInfo to the Interest name, compute an HmacWithSha256
   * signature for the name components and append a final name component with
   * the signature bits.
   * @note This method is an experimental feature. The API may change.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param key The key for the HmacWithSha256.
   * @param keyName The name of the key for the KeyLocator in the SignatureInfo.
   * @param wireFormat A WireFormat object used to encode the input.
   */
  public static void
  signWithHmacWithSha256
    (Interest interest, Blob key, Name keyName, WireFormat wireFormat)
  {
    HmacWithSha256Signature signature = new HmacWithSha256Signature();
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(keyName);

    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signature));
    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());

    // Encode once to get the signed portion.
    SignedBlob encoding = interest.wireEncode(wireFormat);
    byte[] signatureBytes = Common.computeHmacWithSha256
      (key.getImmutableArray(), encoding.signedBuf());
    signature.setSignature(new Blob(signatureBytes, false));

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
  }

  /**
   * Append a SignatureInfo to the Interest name, compute an HmacWithSha256
   * signature for the name components and append a final name component with
   * the signature bits.
   * Use the default WireFormat.getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param key The key for the HmacWithSha256.
   * @param keyName The name of the key for the KeyLocator in the SignatureInfo.
   */
  public static void
  signWithHmacWithSha256(Interest interest, Blob key, Name keyName)
  {
    signWithHmacWithSha256
      (interest, key, keyName, WireFormat.getDefaultWireFormat());
  }

  /**
   * Compute a new HmacWithSha256 for the data packet and verify it against the
   * signature value.
   * @note This method is an experimental feature. The API may change.
   * @param data The Data packet to verify.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat A WireFormat object used to encode the data packet.
   * @return True if the signature verifies, otherwise false.
   */
  public static boolean
  verifyDataWithHmacWithSha256(Data data, Blob key, WireFormat wireFormat)
  {
    // wireEncode returns the cached encoding if available.
    SignedBlob encoding = data.wireEncode(wireFormat);
    byte[] newSignatureBytes = Common.computeHmacWithSha256
      (key.getImmutableArray(), encoding.signedBuf());

    return ByteBuffer.wrap(newSignatureBytes).equals
      (data.getSignature().getSignature().buf());
  }

  /**
   * Compute a new HmacWithSha256 for the data packet and verify it against the
   * signature value.
   * Use the default WireFormat.getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   * @param data The Data packet to verify.
   * @param key The key for the HmacWithSha256.
   * @return True if the signature verifies, otherwise false.
   */
  public static boolean
  verifyDataWithHmacWithSha256(Data data, Blob key)
  {
    return verifyDataWithHmacWithSha256
      (data, key, WireFormat.getDefaultWireFormat());
  }

  /**
   * Compute a new HmacWithSha256 for all but the final name component and
   * verify it against the signature value in the final name component.
   * @note This method is an experimental feature. The API may change.
   * @param interest The Interest object to verify.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat A WireFormat object used to encode the input.
   * @return True if the signature verifies, otherwise false.
   */
  public static boolean
  verifyInterestWithHmacWithSha256
    (Interest interest, Blob key, WireFormat wireFormat)
  {
    Signature signature;
    try {
      // Decode the last two name components of the signed interest.
      signature = wireFormat.decodeSignatureInfoAndValue
        (interest.getName().get(-2).getValue().buf(),
         interest.getName().get(-1).getValue().buf());
    } catch (EncodingException ex) {
      // Treat a decoding error as a verification failure.
      return false;
    }

    // wireEncode returns the cached encoding if available.
    SignedBlob encoding = interest.wireEncode(wireFormat);
    byte[] newSignatureBytes = Common.computeHmacWithSha256
      (key.getImmutableArray(), encoding.signedBuf());

    return ByteBuffer.wrap(newSignatureBytes).equals
      (signature.getSignature().buf());
  }

  /**
   * Compute a new HmacWithSha256 for all but the final name component and
   * verify it against the signature value in the final name component.
   * Use the default WireFormat.getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   * @param interest The Interest object to verify.
   * @param key The key for the HmacWithSha256.
   * @return True if the signature verifies, otherwise false.
   */
  public static boolean
  verifyInterestWithHmacWithSha256(Interest interest, Blob key)
  {
    return verifyInterestWithHmacWithSha256
      (interest, key, WireFormat.getDefaultWireFormat());
  }

  public static KeyParams
  getDefaultKeyParams() { return defaultKeyParams_; }

  /**
   * @deprecated Use getDefaultKeyParams().
   */
  public static final RsaKeyParams DEFAULT_KEY_PARAMS = new RsaKeyParams();

  // Private security v2 methods

  /**
   * Do the work of the constructor.
   */
  private void
  construct(String pibLocator, String tpmLocator, boolean allowReset)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    // PIB locator.
    String[] pibScheme = new String[1];
    String[] pibLocation = new String[1];
    parseAndCheckPibLocator(pibLocator, pibScheme, pibLocation);
    String canonicalPibLocator = pibScheme[0] + ":" + pibLocation[0];

    // Create the PIB.
    pib_ = createPib(canonicalPibLocator);
    String oldTpmLocator = "";
    try {
      oldTpmLocator = pib_.getTpmLocator();
    }
    catch (Pib.Error ex) {
      // The TPM locator is not set in the PIB yet.
    }

    // TPM locator.
    String[] tpmScheme = new String[1];
    String[] tpmLocation = new String[1];
    parseAndCheckTpmLocator(tpmLocator, tpmScheme, tpmLocation);
    String canonicalTpmLocator = tpmScheme[0] + ":" + tpmLocation[0];

    ConfigFile config = new ConfigFile();
    if (canonicalPibLocator.equals(getDefaultPibLocator(config))) {
      // The default PIB must use the default TPM.
      if (!oldTpmLocator.equals("") &&
          !oldTpmLocator.equals(getDefaultTpmLocator(config))) {
        pib_.reset_();
        canonicalTpmLocator = getDefaultTpmLocator(config);
      }
    }
    else {
      // Check the consistency of the non-default PIB.
      if (!oldTpmLocator.equals("") &&
          !oldTpmLocator.equals(canonicalTpmLocator)) {
        if (allowReset)
          pib_.reset_();
        else
          throw new LocatorMismatchError
            ("The supplied TPM locator does not match the TPM locator in the PIB: " +
             oldTpmLocator + " != " + canonicalTpmLocator);
      }
    }

    // Note that a key mismatch may still happen if the TPM locator is initially
    // set to a wrong one or if the PIB was shared by more than one TPM before.
    // This is due to the old PIB not having TPM info. The new PIB should not
    // have this problem.
    tpm_ = createTpm(canonicalTpmLocator);
    pib_.setTpmLocator(canonicalTpmLocator);

    // Provide a default NoVerifyPolicyManager, assuming the application will
    // use a Validator.
    policyManager_ = new NoVerifyPolicyManager();
  }

  /**
   * Get the PIB factories map. On the first call, this initializes the map with
   * factories for standard PibImpl implementations.
   * @return A map where the key is the scheme string and the value is the
   * object implementing makePibImpl.
   */
  private static HashMap<String, MakePibImpl>
  getPibFactories()
  {
    if (pibFactories_ == null) {
      pibFactories_ = new HashMap<String, MakePibImpl>();

      // Add the standard factories.
      pibFactories_.put(PibSqlite3.getScheme(), new MakePibImpl() {
        public PibImpl makePibImpl(String location) throws PibImpl.Error {
          return new PibSqlite3(location);
        }
      });
      pibFactories_.put(PibMemory.getScheme(), new MakePibImpl() {
        public PibImpl makePibImpl(String location) throws PibImpl.Error {
          return new PibMemory();
        }
      });
    }

    return pibFactories_;
  }

  /**
   * Get the TPM factories map. On the first call, this initializes the map with
   * factories for standard TpmBackEnd implementations.
   * @return A map where the key is the scheme string and the value is the
   * object implementing makeTpmBackEnd.
   */
  private static HashMap<String, MakeTpmBackEnd>
  getTpmFactories()
  {
    if (tpmFactories_ == null) {
      tpmFactories_ = new HashMap<String, MakeTpmBackEnd>();

      // Add the standard factories.
      tpmFactories_.put(TpmBackEndFile.getScheme(), new MakeTpmBackEnd() {
        public TpmBackEnd makeTpmBackEnd(String location) {
          return new TpmBackEndFile(location);
        }
      });
      tpmFactories_.put(TpmBackEndMemory.getScheme(), new MakeTpmBackEnd() {
        public TpmBackEnd makeTpmBackEnd(String location) {
          return new TpmBackEndMemory();
        }
      });
    }

    return tpmFactories_;
  }

  /**
   * Parse the uri and set the scheme and location.
   * @param uri The URI to parse.
   * @param scheme Set scheme[0] to the scheme.
   * @param location Set location[0] to the location.
   */
  private static void
  parseLocatorUri(String uri, String[] scheme, String[] location)
  {
    int iColon = uri.indexOf(':');
    if (iColon >= 0) {
      scheme[0] = uri.substring(0, iColon);
      location[0] = uri.substring(iColon + 1);
    }
    else {
      scheme[0] = uri;
      location[0] = "";
    }
  }

  /**
   * Parse the pibLocator and set the pibScheme and pibLocation.
   * @param pibLocator The PIB locator to parse.
   * @param pibScheme Set pibScheme[0] to the PIB scheme.
   * @param pibLocation Set pibLocation[0] to the PIB location.
   */
  private static void
  parseAndCheckPibLocator
    (String pibLocator, String[] pibScheme, String[] pibLocation)
    throws KeyChain.Error
  {
    parseLocatorUri(pibLocator, pibScheme, pibLocation);

    if (pibScheme[0].equals(""))
      pibScheme[0] = getDefaultPibScheme();

    if (!getPibFactories().containsKey(pibScheme[0]))
      throw new KeyChain.Error("PIB scheme `" + pibScheme[0] +
        "` is not supported");
  }

  /**
   * Parse the tpmLocator and set the tpmScheme and tpmLocation.
   * @param tpmLocator The TPM locator to parse.
   * @param tpmScheme Set tpmScheme[0] to the TPM scheme.
   * @param tpmLocation Set tpmLocation[0] to the TPM location.
   */
  private static void
  parseAndCheckTpmLocator
    (String tpmLocator, String[] tpmScheme, String[] tpmLocation)
    throws SecurityException, Error
  {
    parseLocatorUri(tpmLocator, tpmScheme, tpmLocation);

    if (tpmScheme[0].equals(""))
      tpmScheme[0] = getDefaultTpmScheme();

    if (!getTpmFactories().containsKey(tpmScheme[0]))
      throw new KeyChain.Error("TPM scheme `" + tpmScheme[0] +
        "` is not supported");
  }

  private static String
  getDefaultPibScheme() { return PibSqlite3.getScheme(); }

  private static String
  getDefaultTpmScheme() throws SecurityException
  {
    if (Common.platformIsOSX())
      throw new SecurityException
        ("TpmBackEndOsx is not implemented yet. You must use tpm-file.");

    return TpmBackEndFile.getScheme();
  }

  /**
   * Create a Pib according to the pibLocator
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @return A new Pib object.
   */
  private static Pib
  createPib(String pibLocator) throws KeyChain.Error, PibImpl.Error
  {
    String[] pibScheme = new String[1];
    String[] pibLocation = new String[1];
    parseAndCheckPibLocator(pibLocator, pibScheme, pibLocation);
    MakePibImpl pibFactory = getPibFactories().get(pibScheme[0]);
    return new Pib
      (pibScheme[0], pibLocation[0], pibFactory.makePibImpl(pibLocation[0]));
  }

  /**
   * Create a Tpm according to the tpmLocator
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @return A new Tpm object.
   */
  private static Tpm
  createTpm(String tpmLocator) throws SecurityException, KeyChain.Error
  {
    String[] tpmScheme = new String[1];
    String[] tpmLocation = new String[1];
    parseAndCheckTpmLocator(tpmLocator, tpmScheme, tpmLocation);
    MakeTpmBackEnd tpmFactory = getTpmFactories().get(tpmScheme[0]);
    return new Tpm
      (tpmScheme[0], tpmLocation[0], tpmFactory.makeTpmBackEnd(tpmLocation[0]));
  }

  private static String
  getDefaultPibLocator(ConfigFile config)
  {
    if (defaultPibLocator_ != null)
      return defaultPibLocator_;

    String clientPib = System.getenv("NDN_CLIENT_PIB");
    if (clientPib != null && clientPib != "")
      defaultPibLocator_ = clientPib;
    else
      defaultPibLocator_ = config.get("pib", getDefaultPibScheme() + ":");

    return defaultPibLocator_;
  }

  private static String
  getDefaultTpmLocator(ConfigFile config) throws SecurityException
  {
    if (defaultTpmLocator_ != null)
      return defaultTpmLocator_;

    String clientTpm = System.getenv("NDN_CLIENT_TPM");
    if (clientTpm != null && clientTpm != "")
      defaultTpmLocator_ = clientTpm;
    else
      defaultTpmLocator_ = config.get("tpm", getDefaultTpmScheme() + ":");

    return defaultTpmLocator_;
  }

  /**
   * Prepare a Signature object according to signingInfo and get the signing key
   * name.
   * @param params The signing parameters.
   * @param keyName Set keyName[0] to the signing key name.
   * @return A new Signature object with the SignatureInfo.
   * @throws InvalidSigningInfoError when the requested signing method cannot be
   * satisfied.
   */
  private Signature
  prepareSignatureInfo(SigningInfo params, Name[] keyName)
    throws PibImpl.Error, InvalidSigningInfoError, KeyChain.Error
  {
    PibIdentity identity = null;
    PibKey key = null;

    if (params.getSignerType() == SignerType.NULL) {
      try {
        identity = pib_.getDefaultIdentity();
      }
      catch (Pib.Error ex) {
        // There is no default identity, so use sha256 for signing.
        keyName[0] = SigningInfo.getDigestSha256Identity();
        return new DigestSha256Signature();
      }
    }
    else if (params.getSignerType() == SignerType.ID) {
      identity = params.getPibIdentity();
      if (identity == null) {
        try {
          identity = pib_.getIdentity(params.getSignerName());
        }
        catch (Pib.Error ex) {
          throw new InvalidSigningInfoError
            ("Signing identity `" + params.getSignerName().toUri() +
             "` does not exist");
        }
      }
    }
    else if (params.getSignerType() == SignerType.KEY) {
      key = params.getPibKey();
      if (key == null) {
        Name identityName = PibKey.extractIdentityFromKeyName
          (params.getSignerName());

        try {
          identity = pib_.getIdentity(identityName);
          key = identity.getKey(params.getSignerName());
          // We will use the PIB key instance, so reset the identity.
          identity = null;
        }
        catch (Pib.Error ex) {
          throw new InvalidSigningInfoError
            ("Signing key `" + params.getSignerName().toUri() +
             "` does not exist");
        }
      }
    }
    else if (params.getSignerType() == SignerType.CERT) {
      Name identityName = CertificateV2.extractIdentityFromCertName
        (params.getSignerName());

      try {
        identity = pib_.getIdentity(identityName);
        key = identity.getKey
          (CertificateV2.extractKeyNameFromCertName(params.getSignerName()));
      }
      catch (Pib.Error ex) {
        throw new InvalidSigningInfoError
          ("Signing certificate `" + params.getSignerName().toUri() +
           "` does not exist");
      }
    }
    else if (params.getSignerType() == SignerType.SHA256) {
      keyName[0] = SigningInfo.getDigestSha256Identity();
      return new DigestSha256Signature();
    }
    else
      // We don't expect this to happen.
      throw new InvalidSigningInfoError("Unrecognized signer type");

    if (identity == null && key == null)
      throw new InvalidSigningInfoError("Cannot determine signing parameters");

    if (identity != null && key == null) {
      try {
        key = identity.getDefaultKey();
      }
      catch (Pib.Error ex) {
        throw new InvalidSigningInfoError
          ("Signing identity `" + identity.getName().toUri() +
           "` does not have default certificate");
      }
    }

    Signature signatureInfo;

    if (key.getKeyType() == KeyType.RSA &&
        params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
      signatureInfo = new Sha256WithRsaSignature();
    else if (key.getKeyType() == KeyType.EC &&
             params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
      signatureInfo = new Sha256WithEcdsaSignature();
    else
      throw new KeyChain.Error("Unsupported key type");

    if (params.getValidityPeriod().hasPeriod() &&
        ValidityPeriod.canGetFromSignature(signatureInfo))
      // Set the ValidityPeriod from the SigningInfo params.
      ValidityPeriod.getFromSignature(signatureInfo).setPeriod
        (params.getValidityPeriod().getNotBefore(),
         params.getValidityPeriod().getNotAfter());

    KeyLocator keyLocator = KeyLocator.getFromSignature(signatureInfo);
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(key.getName());

    keyName[0] = key.getName();
    return signatureInfo;
  }

  /**
   * Sign the byte array using the key with name keyName.
   * @param buffer The byte buffer to be signed.
   * @param keyName The name of the key.
   * @param digestAlgorithm The digest algorithm.
   * @return The signature Blob, or an isNull Blob if the key does not exist, or
   * for an unrecognized digestAlgorithm.
   */
  private Blob
  sign(ByteBuffer buffer, Name keyName, DigestAlgorithm digestAlgorithm)
    throws TpmBackEnd.Error
  {
    if (keyName.equals(SigningInfo.getDigestSha256Identity()))
      return new Blob(Common.digestSha256(buffer));

    return tpm_.sign(buffer, keyName, digestAlgorithm);
  }

  // Private security v1 methods

  /**
   * A VerifyCallbacks is used for callbacks from verifyData.
   */
  private class VerifyCallbacks implements OnData, OnTimeout {
    public VerifyCallbacks
      (ValidationRequest nextStep, int retry,
       OnDataValidationFailed onValidationFailed, Data originalData)
    {
      nextStep_ = nextStep;
      retry_ = retry;
      onValidationFailed_ = onValidationFailed;
      originalData_ = originalData;
    }

    public final void onData(Interest interest, Data data)
    {
      try {
        // Try to verify the certificate (data) according to the parameters in
        //   nextStep.
        verifyData
          (data, nextStep_.onVerified_, nextStep_.onValidationFailed_,
           nextStep_.stepCount_);
      } catch (SecurityException ex) {
        Logger.getLogger(KeyChain.class.getName()).log(Level.SEVERE, null, ex);
      }
    }

    public final void onTimeout(Interest interest)
    {
      if (retry_ > 0) {
        // Issue the same expressInterest as in verifyData except decrement
        //   retry.
        VerifyCallbacks callbacks = new VerifyCallbacks
          (nextStep_, retry_ - 1, onValidationFailed_, originalData_);
        try {
          face_.expressInterest(interest, callbacks, callbacks);
        }
        catch (IOException ex) {
          try {
            onValidationFailed_.onDataValidationFailed
              (originalData_,
               "Error in expressInterest to retry after timeout for fetching " +
               interest.getName().toUri() + ": " + ex);
          } catch (Throwable exception) {
            logger_.log(Level.SEVERE, "Error in onDataValidationFailed", exception);
          }
        }
      }
      else {
        try {
          onValidationFailed_.onDataValidationFailed
            (originalData_,
               "The retry count is zero after timeout for fetching " +
               interest.getName().toUri());
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onDataValidationFailed", ex);
        }
      }
    }

    private final ValidationRequest nextStep_;
    private final int retry_;
    private final OnDataValidationFailed onValidationFailed_;
    private final Data originalData_;
  }

  /**
   * A VerifyCallbacksForVerifyInterest is used for callbacks from verifyInterest.
   * This is the same as VerifyCallbacks, but we call
   * onValidationFailed.onInterestValidationFailed(originalInterest, reason) if
   * we have too many retries.
   */
  private class VerifyCallbacksForVerifyInterest implements OnData, OnTimeout {
    public VerifyCallbacksForVerifyInterest
      (ValidationRequest nextStep, int retry,
       OnInterestValidationFailed onValidationFailed, Interest originalInterest)
    {
      nextStep_ = nextStep;
      retry_ = retry;
      onValidationFailed_ = onValidationFailed;
      originalInterest_ = originalInterest;
    }

    public final void onData(Interest interest, Data data)
    {
      try {
        // Try to verify the certificate (data) according to the parameters in
        //   nextStep.
        verifyData
          (data, nextStep_.onVerified_, nextStep_.onValidationFailed_,
           nextStep_.stepCount_);
      } catch (SecurityException ex) {
        Logger.getLogger(KeyChain.class.getName()).log(Level.SEVERE, null, ex);
      }
    }

    public final void onTimeout(Interest interest)
    {
      if (retry_ > 0) {
        // Issue the same expressInterest as in verifyData except decrement
        //   retry.
        VerifyCallbacksForVerifyInterest callbacks = new VerifyCallbacksForVerifyInterest
          (nextStep_, retry_ - 1, onValidationFailed_, originalInterest_);
        try {
          face_.expressInterest(interest, callbacks, callbacks);
        }
        catch (IOException ex) {
          try {
            onValidationFailed_.onInterestValidationFailed
              (originalInterest_,
               "Error in expressInterest to retry after timeout for fetching " +
               interest.getName().toUri() + ": " + ex);
          } catch (Throwable exception) {
            logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", exception);
          }
        }
      }
      else {
        try {
          onValidationFailed_.onInterestValidationFailed
            (originalInterest_,
               "The retry count is zero after timeout for fetching " +
               interest.getName().toUri());
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", ex);
        }
      }
    }

    private final ValidationRequest nextStep_;
    private final int retry_;
    private final OnInterestValidationFailed onValidationFailed_;
    private final Interest originalInterest_;
  }

  /**
   * Get the default certificate from the identity storage and return its name.
   * If there is no default identity or default certificate, then create one.
   * @return The default certificate name.
   */
  private Name
  prepareDefaultCertificateName() throws SecurityException
  {
    IdentityCertificate signingCertificate =
      identityManager_.getDefaultCertificate();
    if (signingCertificate == null) {
      setDefaultCertificate();
      signingCertificate = identityManager_.getDefaultCertificate();
    }

    return signingCertificate.getName();
  }

  /**
   * Create the default certificate if it is not initialized. If there is no
   * default identity yet, creating a new tmp-identity.
   */
  private void
  setDefaultCertificate() throws SecurityException
  {
    if (identityManager_.getDefaultCertificate() == null) {
      Name defaultIdentity;
      try {
        defaultIdentity = identityManager_.getDefaultIdentity();
      } catch (SecurityException e) {
        // Create a default identity name.
        ByteBuffer randomComponent = ByteBuffer.allocate(4);
        Common.getRandom().nextBytes(randomComponent.array());
        defaultIdentity = new Name().append("tmp-identity")
          .append(new Blob(randomComponent, false));
      }

      createIdentityAndCertificate(defaultIdentity);
      identityManager_.setDefaultIdentity(defaultIdentity);
    }
  }

  private boolean isSecurityV1_;

  private IdentityManager identityManager_; // for security v1
  private PolicyManager policyManager_;     // for security v1
  private Face face_ = null; // for security v1

  private Pib pib_;
  private Tpm tpm_;

  private static String defaultPibLocator_ = null;
  private static String defaultTpmLocator_ = null;
  private static HashMap<String, MakePibImpl> pibFactories_ = null;
  private static HashMap<String, MakeTpmBackEnd> tpmFactories_ = null;
  private static final SigningInfo defaultSigningInfo_ = new SigningInfo();
  private static final KeyParams defaultKeyParams_ = new RsaKeyParams();

  private static final Logger logger_ = Logger.getLogger(KeyChain.class.getName());
}
