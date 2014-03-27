/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.encryption.EncryptionManager;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.policy.PolicyManager;

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
  public KeyChain
    (IdentityManager identityManager, PolicyManager policyManager)
  {
    identityManager_ = identityManager;
    policyManager_ = policyManager;
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
  public void 
  sign(Data data, Name certificateName, WireFormat wireFormat) throws SecurityException
  {
    identityManager_.signByCertificate(data, certificateName, wireFormat);
  }

  /**
   * Wire encode the Data object, sign it and set its signature.
   * Use the default WireFormat.getDefaultWireFormat()
   * @param data The Data object to be signed.  This updates its signature and 
   * key locator field and wireEncoding.
   * @param certificateName The certificate name of the key to use for signing.
   */
  public void 
  sign(Data data, Name certificateName) throws SecurityException
  {
    sign(data, certificateName, WireFormat.getDefaultWireFormat());
  }
  
  /**
   * Sign the byte buffer using a certificate name and return a Signature object.
   * @param buffer The byte array to be signed.
   * @param bufferLength the length of buffer.
   * @param certificateName The certificate name used to get the signing key and which will be put into KeyLocator.
   * @return The Signature.
   */
  public Signature
  sign(ByteBuffer buffer, Name certificateName) throws SecurityException
  {
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
  public void 
  signByIdentity
    (Data data, Name identityName, WireFormat wireFormat) throws SecurityException
  {
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
  public void 
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
  public void 
  signByIdentity(Data data) throws SecurityException
  {
    signByIdentity(data, new Name(), WireFormat.getDefaultWireFormat());
  }

  /**
   * Sign the byte buffer using an identity name and return a Signature object.
   * @param buffer The byte array to be signed.
   * @param bufferLength the length of buffer.
   * @param identityName The identity name.
   * @return The Signature.
   */
  public Signature
  signByIdentity(ByteBuffer buffer, Name identityName) throws SecurityException
  {
    Name signingCertificateName = 
      identityManager_.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException("No qualified certificate name found!");

    return identityManager_.signByCertificate(buffer, signingCertificateName);
  }

  public void
  verifyData
    (Data data, OnVerified onVerified, OnVerifyFailed onVerifyFailed, 
     int stepCount)
  {
  }
  
  /**
   * Check the signature on the Data object and call either onVerify.onVerify or 
   * onVerifyFailed.onVerifyFailed. 
   * We use callback functions because verify may fetch information to check the 
   * signature.
   * @param data The Data object with the signature to check. It is an error if 
   * data does not have a wireEncoding. 
   * To set the wireEncoding, you can call data.wireDecode.
   * @param onVerified If the signature is verified, this calls 
   * onVerified.onVerified(data).
   * @param onVerifyFailed If the signature check fails, this calls 
   * onVerifyFailed.onVerifyFailed(data).
   */
  public void
  verifyData(Data data, OnVerified onVerified, OnVerifyFailed onVerifyFailed)
  {
    verifyData(data, onVerified, onVerifyFailed, 0);
  }

  
  
  /**
   * Set the Face which will be used to fetch required certificates.
   * @param face A pointer to the Face object.
   */
  public void
  setFace(Face face) { face_ = face; }
  
  IdentityManager identityManager_;
  PolicyManager policyManager_;
  EncryptionManager encryptionManager_;
  Face face_ = null;
  int maxSteps_ = 100;
}
