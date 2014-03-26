/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

import net.named_data.jndn.Interest;

public class ValidationRequest {
  public ValidationRequest(Interest interest, OnVerified onVerified, OnVerifyFailed onVerifyFailed, int retry, int stepCount)
  {
    interest_ = interest;
    onVerified_ = onVerified;
    onVerifyFailed_ = onVerifyFailed;
    retry_ = retry;
    stepCount_ = stepCount;
  }
    
  public final Interest interest_;             // An interest packet to fetch the requested data.
  public final OnVerified onVerified_;         // A callback function if the requested certificate has been validated.
  public final OnVerifyFailed onVerifyFailed_; // A callback function if the requested certificate cannot be validated.
  public final int retry_;                     // The number of retrials when there is an interest timeout.
  public final int stepCount_;
}
