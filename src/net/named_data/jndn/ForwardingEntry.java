/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A ForwardingEntry holds an action and Name prefix and other fields for a
 * forwarding entry.
 */
public class ForwardingEntry {

  public final String
  getAction() { return action_; }
  
  public final Name
  getPrefix() { return prefix_; }
  
  public final PublisherPublicKeyDigest
  getPublisherPublicKeyDigest() { return publisherPublicKeyDigest_; }
  
  public final int 
  getFaceId() { return faceId_; }

  public final ForwardingFlags
  getForwardingFlags() { return forwardingFlags_; }

  public final double
  getFreshnessPeriod() { return freshnessPeriod_; }

  public final void 
  setAction(String action) { action_ = action == null ? "" : action; }

  public final void 
  setPrefix(Name prefix) 
  { 
    prefix_ = prefix == null ? new Name() : new Name(prefix); 
  }
  
  public final void 
  setFaceId(int faceId) { faceId_ = faceId; }
      
  public final void 
  setForwardingFlags(ForwardingFlags forwardingFlags) 
  { 
    forwardingFlags_ = forwardingFlags == null ? 
      new ForwardingFlags() : new ForwardingFlags(forwardingFlags); 
  }
      
  public final void 
  setFreshnessPeriod(double freshnessPeriod) 
  { 
    freshnessPeriod_ = freshnessPeriod; 
  }

  private String action_ = ""; /**< "" for none. */
  private Name prefix_ = new Name();
  private PublisherPublicKeyDigest publisherPublicKeyDigest_ =
    new PublisherPublicKeyDigest();
  private int faceId_ = -1; /**< -1 for none. */
  private ForwardingFlags forwardingFlags_ = new ForwardingFlags();
  private double freshnessPeriod_ = -1.0; /**< Milliseconds. -1 for none. */
}
