/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security.policy;

import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifyFailed;
import net.named_data.jndn.security.ValidationRequest;

/**
 * A PolicyManager is an abstract base class to represent the policy for verifying data packets.
 * You must create an object of a subclass.
 */
public abstract class PolicyManager {
  /**
   * Check if the received data packet can escape from verification and be trusted as valid.
   * @param data The received data packet.
   * @return true if the data does not need to be verified to be trusted as valid, otherwise false.
   */
  public abstract boolean 
  skipVerifyAndTrust(Data data);

  /**
   * Check if this PolicyManager has a verification rule for the received data.
   * @param data The received data packet.
   * @return true if the data must be verified, otherwise false.
   */
  public abstract boolean
  requireVerify(Data data);

  /**
   * Check whether the received data packet complies with the verification policy, and get the indication of the next verification step.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done, used to track the verification progress.
   * @param onVerified If the signature is verified, this calls onVerified(data).
   * @param onVerifyFailed If the signature check fails, this calls onVerifyFailed(data).
   * @return the indication of next verification step, null if there is no further step.
   */
  public abstract ValidationRequest
  checkVerificationPolicy(Data data, int stepCount, OnVerified onVerified, OnVerifyFailed onVerifyFailed);
    
  /**
   * Check if the signing certificate name and data name satisfy the signing policy.
   * @param dataName The name of data to be signed.
   * @param certificateName The name of signing certificate.
   * @return true if the signing certificate can be used to sign the data, otherwise false.
   */
  public abstract boolean
  checkSigningPolicy(Name dataName, Name certificateName);
    
  /**
   * Infer the signing identity name according to the policy. If the signing identity cannot be inferred, return an empty name.
   * @param dataName The name of data to be signed.
   * @return The signing identity or an empty name if cannot infer. 
   */
  public abstract Name 
  inferSigningIdentity(Name dataName);
}
