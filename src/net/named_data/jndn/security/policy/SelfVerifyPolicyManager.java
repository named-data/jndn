/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.security.policy;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifyFailed;
import net.named_data.jndn.security.ValidationRequest;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.identity.IdentityStorage;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SignedBlob;

/**
 * A SelfVerifyPolicyManager implements a PolicyManager to use the public key
 * DER in the data packet's KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet, without searching a
 * certificate chain.  If the public key can't be found, the verification fails.
 */
public class SelfVerifyPolicyManager extends PolicyManager {
  /**
   * Create a new SelfVerifyPolicyManager which will look up the public key in
   * the given identityStorage.
   * @param identityStorage The IdentityStorage for looking up the
   * public key.  This points to an object must which remain valid during the
   * life of this SelfVerifyPolicyManager.
   */
  public SelfVerifyPolicyManager(IdentityStorage identityStorage)
  {
    identityStorage_ = identityStorage;
  }

  /**
   * Create a new SelfVerifyPolicyManager which will look up the public key in
   * the given identityStorage.
   * Since there is no IdentotyStorage, don't look for a public key with the
   * name in the KeyLocator and rely on the KeyLocator having the full public
   * key DER.
   */
  public SelfVerifyPolicyManager()
  {
    identityStorage_ = null;
  }

  /**
   * Never skip verification.
   * @param data The received data packet.
   * @return false.
   */
  public boolean skipVerifyAndTrust(Data data)
  {
    return false;
  }

  /**
   * Always return true to use the self-verification rule for the received data.
   * @param data The received data packet.
   * @return true.
   */
  public boolean requireVerify(Data data)
  {
    return true;
  }

  /**
   * Use the public key DER in the data packet's KeyLocator (if available) or
   * look in the IdentityStorage for the public key with the name in the
   * KeyLocator (if available) and use it to verify the data packet.  If the
   * public key can't be found, call onVerifyFailed.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress. (stepCount is ignored.)
   * @param onVerified If the signature is verified, this calls onVerified(data).
   * @param onVerifyFailed If the signature check fails or can't find the public
   * key, this calls onVerifyFailed(data).
   * @return null for no further step for looking up a certificate chain.
   */
  public ValidationRequest checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified,
     OnVerifyFailed onVerifyFailed)
  {
    // wireEncode returns the cached encoding if available.
    if (verify(data.getSignature(), data.wireEncode()))
      onVerified.onVerified(data);
    else
      onVerifyFailed.onVerifyFailed(data);

    // No more steps, so return a null ValidationRequest.
    return null;
  }

  /**
   * Override to always indicate that the signing certificate name and data name
   * satisfy the signing policy.
   * @param dataName The name of data to be signed.
   * @param certificateName The name of signing certificate.
   * @return true to indicate that the signing certificate can be used to sign
   * the data.
   */
  public boolean checkSigningPolicy(Name dataName, Name certificateName)
  {
    return true;
  }

  /**
   * Override to indicate that the signing identity cannot be inferred.
   * @param dataName The name of data to be signed.
   * @return An empty name because cannot infer.
   */
  public Name inferSigningIdentity(Name dataName)
  {
    return new Name();
  }

  /**
   * Check the type of signatureInfo to get the KeyLocator. Use the public key
   * DER in the KeyLocator (if available) or look in the IdentityStorage for the
   * public key with the name in the KeyLocator (if available) and use it to
   * verify the signedBlob. If the public key can't be found, return false.
   * (This is a generalized method which can verify both a Data packet and an
   * interest.)
   * @param signatureInfo An object of a subclass of Signature, e.g.
   * Sha256WithRsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @return True if the signature is verified, false if failed.
   */
  private boolean
  verify(net.named_data.jndn.Signature signatureInfo, SignedBlob signedBlob)
  {
    if (!(signatureInfo instanceof Sha256WithRsaSignature))
      throw new SecurityException("SelfVerifyPolicyManager: Signature is not Sha256WithRsaSignature.");
    Sha256WithRsaSignature signature =
      (Sha256WithRsaSignature)signatureInfo;

    if (signature.getKeyLocator().getType() == KeyLocatorType.KEY) {
      // Use the public key DER directly.
      // wireEncode returns the cached encoding if available.
      if (verifySha256WithRsaSignature
          (signature, signedBlob, signature.getKeyLocator().getKeyData()))
        return true;
      else
        return false;
    }
    else if (signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME &&
             identityStorage_ != null) {
      // Assume the key name is a certificate name.
      Blob publicKeyDer = identityStorage_.getKey
        (IdentityCertificate.certificateNameToPublicKeyName
         (signature.getKeyLocator().getKeyName()));
      if (publicKeyDer.isNull())
        // Can't find the public key with the name.
        return false;

      if (verifySha256WithRsaSignature
          (signature, signedBlob, publicKeyDer))
        return true;
      else
        return false;
    }
    else
      // Can't find a key to verify.
      return false;
  }

  /**
   * Verify the RSA signature on the SignedBlob using the given public key.
   * TODO: Move this general verification code to a more central location.
   * @param signature The Sha256WithRsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param publicKeyDer The DER-encoded public key used to verify the signature.
   * @return true if the signature verifies, false if not.
   * @throws SecurityException if data does not have a Sha256WithRsaSignature.
   */
  private static boolean
  verifySha256WithRsaSignature
    (Sha256WithRsaSignature signature, SignedBlob signedBlob, Blob publicKeyDer)
  {
    if (signature.getDigestAlgorithm().size() != 0)
      // TODO: Allow a non-default digest algorithm.
      throw new SecurityException
        ("Cannot verify a data packet with a non-default digest algorithm.");

    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("RSA is not supported: " + exception.getMessage());
    }

    PublicKey publicKey = null;
    try {
      publicKey = keyFactory.generatePublic
        (new X509EncodedKeySpec(publicKeyDer.getImmutableArray()));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("X509EncodedKeySpec is not supported: " + exception.getMessage());
    }

    Signature rsaSignature = null;
    try {
      rsaSignature = Signature.getInstance("SHA256withRSA");
    }
    catch (NoSuchAlgorithmException e) {
      // Don't expect this to happen.
      throw new SecurityException("SHA256withRSA algorithm is not supported");
    }

    try {
      rsaSignature.initVerify(publicKey);
    }
    catch (InvalidKeyException exception) {
      throw new SecurityException
        ("InvalidKeyException: " + exception.getMessage());
    }
    try {
      // wireEncode returns the cached encoding if available.
      rsaSignature.update(signedBlob.signedBuf());
      return rsaSignature.verify(signature.getSignature().getImmutableArray());
    }
    catch (SignatureException exception) {
      throw new SecurityException
        ("SignatureException: " + exception.getMessage());
    }
  }

  /**
   * Verify the ECDSA signature on the SignedBlob using the given public key.
   * TODO: Move this general verification code to a more central location.
   * @param signature The Sha256WithEcdsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param publicKeyDer The DER-encoded public key used to verify the signature.
   * @return true if the signature verifies, false if not.
   * @throws SecurityException if data does not have a Sha256WithEcdsaSignature.
   */
  private static boolean
  verifySha256WithEcdsaSignature
    (
     //Sha256WithEcdsaSignature signature,
     Sha256WithRsaSignature signature,
     SignedBlob signedBlob, Blob publicKeyDer)
  {
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("EC");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("EC is not supported: " + exception.getMessage());
    }

    PublicKey publicKey = null;
    try {
      publicKey = keyFactory.generatePublic
        (new X509EncodedKeySpec(publicKeyDer.getImmutableArray()));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("X509EncodedKeySpec is not supported: " + exception.getMessage());
    }

    Signature ecSignature = null;
    try {
      ecSignature = Signature.getInstance("SHA256withECDSA");
    }
    catch (NoSuchAlgorithmException e) {
      // Don't expect this to happen.
      throw new SecurityException("SHA256withECDSA algorithm is not supported");
    }

    try {
      ecSignature.initVerify(publicKey);
    }
    catch (InvalidKeyException exception) {
      throw new SecurityException
        ("InvalidKeyException: " + exception.getMessage());
    }
    try {
      // wireEncode returns the cached encoding if available.
      ecSignature.update(signedBlob.signedBuf());
      return ecSignature.verify(signature.getSignature().getImmutableArray());
    }
    catch (SignatureException exception) {
      throw new SecurityException
        ("SignatureException: " + exception.getMessage());
    }
  }

  private final IdentityStorage identityStorage_;
}
