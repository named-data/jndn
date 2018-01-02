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

package net.named_data.jndn.security.policy;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifiedInterest;
import net.named_data.jndn.security.OnDataValidationFailed;
import net.named_data.jndn.security.OnInterestValidationFailed;
import net.named_data.jndn.security.ValidationRequest;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.identity.IdentityStorage;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SignedBlob;

/**
 * A SelfVerifyPolicyManager implements a PolicyManager to look in the
 * storage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet, without searching a
 * certificate chain.  If the public key can't be found, the verification fails.
 */
public class SelfVerifyPolicyManager extends PolicyManager {
  /**
   * Create a new SelfVerifyPolicyManager which will look up the public key in
   * the given identityStorage.
   * @param identityStorage The IdentityStorage for looking up the
   * public key.  This points to an object which must remain valid during the
   * life of this SelfVerifyPolicyManager.
   */
  public SelfVerifyPolicyManager(IdentityStorage identityStorage)
  {
    identityStorage_ = identityStorage;
    pibImpl_ = null;
  }

  /**
   * Create a new SelfVerifyPolicyManager which will look up the public key in
   * the given pibImpl.
   * @param pibImpl The PibImpl for looking up the public key. This points to an
   * object which must remain valid during the life of this
   * SelfVerifyPolicyManager.
   */
  public SelfVerifyPolicyManager(PibImpl pibImpl)
  {
    identityStorage_ = null;
    pibImpl_ = pibImpl;
  }

  /**
   * Create a new SelfVerifyPolicyManager which will rely on the KeyLocator
   * having the full public key DER.
   */
  public SelfVerifyPolicyManager()
  {
    identityStorage_ = null;
    pibImpl_ = null;
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
   * Never skip verification.
   * @param interest The received interest.
   * @return false.
   */
  public boolean skipVerifyAndTrust(Interest interest)
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
   * Always return true to use the self-verification rule for the received interest.
   * @param interest The received interest.
   * @return true.
   */
  public boolean requireVerify(Interest interest)
  {
    return true;
  }

  /**
   * Look in the IdentityStorage or PibImpl for the public key with the name in the
   * KeyLocator (if available) and use it to verify the data packet.  If the
   * public key can't be found, call onValidationFailed.onDataValidationFailed.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress. (stepCount is ignored.)
   * @param onVerified If the signature is verified, this calls onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed If the signature check fails, this calls
   * onValidationFailed.onDataValidationFailed(data, reason).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return null for no further step for looking up a certificate chain.
   */
  public ValidationRequest checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified,
     OnDataValidationFailed onValidationFailed) throws SecurityException
  {
    String[] failureReason = new String[] { "unknown" };
    // wireEncode returns the cached encoding if available.
    if (verify(data.getSignature(), data.wireEncode(), failureReason)) {
      try {
        onVerified.onVerified(data);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerified", ex);
      }
    }
    else {
      try {
        onValidationFailed.onDataValidationFailed(data, failureReason[0]);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onDataValidationFailed", ex);
      }
    }

    // No more steps, so return a null ValidationRequest.
    return null;
  }

  /**
   * Use wireFormat.decodeSignatureInfoAndValue to decode the last two name
   * components of the signed interest. Look in the IdentityStorage or PibImpl for the
   * public key with the name in the KeyLocator (if available) and use it to
   * verify the interest. If the public key can't be found, call
   * onValidationFailed.onInterestValidationFailed.
   * @param interest The interest with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress. (stepCount is ignored.)
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerifiedInterest(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onValidationFailed If the signature check fails or can't find the
   * public key, this calls
   * onValidationFailed.onInterestValidationFailed(interest, reason).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return null for no further step for looking up a certificate chain.
   */
  public ValidationRequest
  checkVerificationPolicy
    (Interest interest, int stepCount, OnVerifiedInterest onVerified,
     OnInterestValidationFailed onValidationFailed, WireFormat wireFormat)
    throws net.named_data.jndn.security.SecurityException
  {
    if (interest.getName().size() < 2) {
      try {
        onValidationFailed.onInterestValidationFailed
          (interest, "The signed interest has less than 2 components: " +
           interest.getName().toUri());
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", exception);
      }
      return null;
    }

    // Decode the last two name components of the signed interest
    Signature signature;
    try {
      signature = wireFormat.decodeSignatureInfoAndValue
        (interest.getName().get(-2).getValue().buf(),
         interest.getName().get(-1).getValue().buf(), false);
    }
    catch (EncodingException ex) {
      logger_.log
        (Level.INFO, "Cannot decode the signed interest SignatureInfo and value", ex);
      try {
        onValidationFailed.onInterestValidationFailed
          (interest, "Error decoding the signed interest signature: " + ex);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", exception);
      }
      return null;
    }

    String[] failureReason = new String[] { "unknown" };
    // wireEncode returns the cached encoding if available.
    if (verify(signature, interest.wireEncode(wireFormat), failureReason)) {
      try {
        onVerified.onVerifiedInterest(interest);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerifiedInterest", ex);
      }
    }
    else {
      try {
        onValidationFailed.onInterestValidationFailed(interest, failureReason[0]);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onInterestValidationFailed", ex);
      }
    }

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
   * Check the type of signatureInfo to get the KeyLocator. Look in the
   * IdentityStorage or PibImpl for the public key with the name in the KeyLocator (if
   * available) and use it to verify the signedBlob. If the public key can't be
   * found, return false. (This is a generalized method which can verify both a
   * Data packet and an interest.)
   * @param signatureInfo An object of a subclass of Signature, e.g.
   * Sha256WithRsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @param failureReason If verification fails, set failureReason[0] to the
   * failure reason.
   * @return True if the signature is verified, false if failed.
   */
  private boolean
  verify(Signature signatureInfo, SignedBlob signedBlob, String[] failureReason)
    throws net.named_data.jndn.security.SecurityException
  {
    Blob publicKeyDer = null;
    if (KeyLocator.canGetFromSignature(signatureInfo)) {
      publicKeyDer = getPublicKeyDer
        (KeyLocator.getFromSignature(signatureInfo), failureReason);
      if (publicKeyDer.isNull())
        return false;
    }

    if (verifySignature(signatureInfo, signedBlob, publicKeyDer))
      return true;
    else {
      failureReason[0] = "The signature did not verify with the given public key";
      return false;
    }
  }

  /**
   * Look in the IdentityStorage or pibImpl for the public key with the name in the
   * KeyLocator (if available). If the public key can't be found, return an
   * empty Blob.
   * @param keyLocator The KeyLocator.
   * @param failureReason If can't find the public key, set failureReason[0] to
   * the failure reason.
   * @return The public key DER or an empty Blob if not found.
   */
  private Blob
  getPublicKeyDer(KeyLocator keyLocator, String[] failureReason)
    throws SecurityException
  {
    if (keyLocator.getType() == KeyLocatorType.KEYNAME &&
             identityStorage_ != null) {
      Name keyName;
      try {
        // Assume the key name is a certificate name.
        keyName = IdentityCertificate.certificateNameToPublicKeyName
           (keyLocator.getKeyName());
      } catch (Throwable ex) {
        failureReason[0] = "Cannot get a public key name from the certificate named: " +
          keyLocator.getKeyName().toUri();
        return new Blob();
      }
      try {
        // Assume the key name is a certificate name.
        return identityStorage_.getKey(keyName);
      } catch (SecurityException ex) {
        failureReason[0] = "The identityStorage doesn't have the key named " +
          keyName.toUri();
        return new Blob();
      }
    }
    else if (keyLocator.getType() == KeyLocatorType.KEYNAME && pibImpl_ != null) {
      try {
        return pibImpl_.getKeyBits(keyLocator.getKeyName());
      } catch (Pib.Error ex) {
        failureReason[0] = "The pibImpl doesn't have the key named " +
          keyLocator.getKeyName().toUri();
        return new Blob();
      } catch (PibImpl.Error ex) {
        failureReason[0] = "Error getting the key named " +
          keyLocator.getKeyName().toUri();
        return new Blob();
      }
    }
    else {
      // Can't find a key to verify.
      failureReason[0] = "The signature KeyLocator doesn't have a key name";
      return new Blob();
    }
  }

  private final IdentityStorage identityStorage_;
  private final PibImpl pibImpl_;
  private static final Logger logger_ = Logger.getLogger
    (SelfVerifyPolicyManager.class.getName());
}
