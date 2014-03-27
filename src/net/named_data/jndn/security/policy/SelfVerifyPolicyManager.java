/**
 * Copyright (C) 2014 Regents of the University of California.
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
import net.named_data.jndn.security.identity.IdentityStorage;

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
  
  private IdentityStorage identityStorage_;

  public boolean skipVerifyAndTrust(Data data) 
  {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public boolean requireVerify(Data data) 
  {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public ValidationRequest checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified, 
     OnVerifyFailed onVerifyFailed) 
  {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public boolean checkSigningPolicy(Name dataName, Name certificateName) 
  {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public Name inferSigningIdentity(Name dataName) 
  {
    throw new UnsupportedOperationException("Not supported yet.");
  }
}
