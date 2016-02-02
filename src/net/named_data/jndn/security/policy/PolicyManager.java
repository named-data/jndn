/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

package net.named_data.jndn.security.policy;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import net.named_data.jndn.Data;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifiedInterest;
import net.named_data.jndn.security.OnVerifyFailed;
import net.named_data.jndn.security.OnVerifyInterestFailed;
import net.named_data.jndn.security.ValidationRequest;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.SignedBlob;

/**
 * A PolicyManager is an abstract base class to represent the policy for
 * verifying data packets.
 * You must create an object of a subclass.
 */
public abstract class PolicyManager {
  /**
   * Check if the received data packet can escape from verification and be
   * trusted as valid.
   * @param data The received data packet.
   * @return true if the data does not need to be verified to be trusted as
   * valid, otherwise false.
   */
  public abstract boolean
  skipVerifyAndTrust(Data data);

  /**
   * Check if the received signed interest can escape from verification and be
   * trusted as valid.
   * @param interest The received interest.
   * @return true if the interest does not need to be verified to be trusted as
   * valid, otherwise false.
   */
  public abstract boolean
  skipVerifyAndTrust(Interest interest);

  /**
   * Check if this PolicyManager has a verification rule for the received data.
   * @param data The received data packet.
   * @return true if the data must be verified, otherwise false.
   */
  public abstract boolean
  requireVerify(Data data);

  /**
   * Check if this PolicyManager has a verification rule for the received interest.
   * @param interest The received interest.
   * @return true if the interest must be verified, otherwise false.
   */
  public abstract boolean
  requireVerify(Interest interest);

  /**
   * Check whether the received data packet complies with the verification
   * policy, and get the indication of the next verification step.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done,
   * used to track the verification progress.
   * @param onVerified If the signature is verified, this calls
   * onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onVerifyFailed If the signature check fails, this calls
   * onVerifyFailed(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return the indication of next verification step, null if there is no
   * further step.
   */
  public abstract ValidationRequest
  checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified,
     OnVerifyFailed onVerifyFailed) throws SecurityException;

  /**
   * Check whether the received signed interest complies with the verification
   * policy, and get the indication of the next verification step.
   * @param interest The interest with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
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
   * @return the indication of next verification step, null if there is no
   * further step.
   */
  public abstract ValidationRequest
  checkVerificationPolicy
    (Interest interest, int stepCount, OnVerifiedInterest onVerified,
     OnVerifyInterestFailed onVerifyFailed, WireFormat wireFormat) throws SecurityException;

  public ValidationRequest
  checkVerificationPolicy
    (Interest interest, int stepCount, OnVerifiedInterest onVerified,
     OnVerifyInterestFailed onVerifyFailed) throws SecurityException
  {
    return checkVerificationPolicy
      (interest, stepCount, onVerified, onVerifyFailed,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Check if the signing certificate name and data name satisfy the signing
   * policy.
   * @param dataName The name of data to be signed.
   * @param certificateName The name of signing certificate.
   * @return true if the signing certificate can be used to sign the data,
   * otherwise false.
   */
  public abstract boolean
  checkSigningPolicy(Name dataName, Name certificateName);

  /**
   * Infer the signing identity name according to the policy. If the signing
   * identity cannot be inferred, return an empty name.
   * @param dataName The name of data to be signed.
   * @return The signing identity or an empty name if cannot infer.
   */
  public abstract Name
  inferSigningIdentity(Name dataName);

  /**
   * Check the type of signature and use the publicKeyDer to verify the
   * signedBlob using the appropriate signature algorithm.
   * @param signature An object of a subclass of Signature, e.g.
   * Sha256WithRsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param publicKeyDer The DER-encoded public key used to verify the signature.
   * This may be null if the signature type does not require a public key.
   * @return True if the signature is verified, false if failed.
   * @throws SecurityException if the signature type is not recognized or if
   * publicKeyDer can't be decoded.
   */
  protected static boolean
  verifySignature
    (net.named_data.jndn.Signature signature, SignedBlob signedBlob,
     Blob publicKeyDer) throws SecurityException
  {
    if (signature instanceof Sha256WithRsaSignature) {
      if (publicKeyDer.isNull())
        return false;
      return verifySha256WithRsaSignature
          (signature.getSignature(), signedBlob, publicKeyDer);
    }
    else if (signature instanceof Sha256WithEcdsaSignature) {
      if (publicKeyDer.isNull())
        return false;
      return verifySha256WithEcdsaSignature
          (signature.getSignature(), signedBlob, publicKeyDer);
    }
    else if (signature instanceof DigestSha256Signature)
      return verifyDigestSha256Signature(signature.getSignature(), signedBlob);
    else
      // We don't expect this to happen.
      throw new SecurityException
        ("PolicyManager.verify: Signature type is unknown");
  }

  /**
   * Verify the RSA signature on the SignedBlob using the given public key.
   * @param signature The signature bits.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param publicKeyDer The DER-encoded public key used to verify the signature.
   * @return true if the signature verifies, false if not.
   */
  protected static boolean
  verifySha256WithRsaSignature
    (Blob signature, SignedBlob signedBlob, Blob publicKeyDer) throws SecurityException
  {
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("RSA is not supported: " + exception.getMessage());
    }

    java.security.PublicKey publicKey = null;
    try {
      publicKey = keyFactory.generatePublic
        (new X509EncodedKeySpec(publicKeyDer.getImmutableArray()));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("X509EncodedKeySpec is not supported: " + exception.getMessage());
    }

    java.security.Signature rsaSignature = null;
    try {
      rsaSignature = java.security.Signature.getInstance("SHA256withRSA");
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
      rsaSignature.update(signedBlob.signedBuf());
      return rsaSignature.verify(signature.getImmutableArray());
    }
    catch (SignatureException exception) {
      throw new SecurityException
        ("SignatureException: " + exception.getMessage());
    }
  }

  /**
   * Verify the ECDSA signature on the SignedBlob using the given public key.
   * @param signature The signature bits.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param publicKeyDer The DER-encoded public key used to verify the signature.
   * @return true if the signature verifies, false if not.
   */
  protected static boolean
  verifySha256WithEcdsaSignature
    (Blob signature, SignedBlob signedBlob, Blob publicKeyDer) throws SecurityException
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

    java.security.PublicKey publicKey = null;
    try {
      publicKey = keyFactory.generatePublic
        (new X509EncodedKeySpec(publicKeyDer.getImmutableArray()));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new SecurityException
        ("X509EncodedKeySpec is not supported: " + exception.getMessage());
    }

    java.security.Signature ecSignature = null;
    try {
      ecSignature = java.security.Signature.getInstance("SHA256withECDSA");
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
      ecSignature.update(signedBlob.signedBuf());
      return ecSignature.verify(signature.getImmutableArray());
    }
    catch (SignatureException exception) {
      throw new SecurityException
        ("SignatureException: " + exception.getMessage());
    }
  }

  /**
   * Verify the DigestSha256 signature on the SignedBlob by verifying that the
   * digest of SignedBlob equals the signature.
   * @param signature The signature bits.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @return true if the signature verifies, false if not.
   */
  protected static boolean
  verifyDigestSha256Signature(Blob signature, SignedBlob signedBlob)
  {
    // Set signedPortionDigest to the digest of the signed portion of the signedBlob.
    byte[] signedPortionDigest = Common.digestSha256(signedBlob.signedBuf());

    return Arrays.equals(signedPortionDigest, signature.getImmutableArray());
  }
}
