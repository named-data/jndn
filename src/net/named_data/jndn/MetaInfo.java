/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

public class MetaInfo {
  /**
   * Create a new MetaInfo with default values.
   */
  public MetaInfo()
  {
  }

  /**
   * Create a new MetaInfo with a copy of the fields in the given metaInfo.
   * @param metaInfo The MetaInfo to copy.
   */
  public MetaInfo(MetaInfo metaInfo)
  {
    timestampMilliseconds_ = metaInfo.timestampMilliseconds_;
    type_ = metaInfo.type_; 
    freshnessSeconds_ = metaInfo.freshnessSeconds_; 
    // Name.Component is read-only, so we don't need a deep copy.
    finalBlockID_ = metaInfo.finalBlockID_;
  }

  public enum ContentType {
    DATA, ENCR, GONE, KEY, LINK, NACK
  }

  public final double 
  getTimestampMilliseconds() { return timestampMilliseconds_; }
  
  public final ContentType 
  getType() { return type_; }
  
  public final int 
  getFreshnessSeconds() { return freshnessSeconds_; }
  
  public final Name.Component 
  getFinalBlockID() { return finalBlockID_; }
  
  public final void 
  setTimestampMilliseconds(double timestampMilliseconds)
  { 
    timestampMilliseconds_ = timestampMilliseconds; 
    ++changeCount_;
  }
  
  public final void 
  setType(ContentType type)
  { 
    type_ = type; 
    ++changeCount_;
  }
  
  public final void 
  setFreshnessSeconds(int freshnessSeconds) 
  { 
    freshnessSeconds_ = freshnessSeconds; 
    ++changeCount_;
  }

  public final void 
  setFinalBlockID(Name.Component finalBlockID) 
  { 
    finalBlockID_ = (finalBlockID == null ? new Name.Component() : finalBlockID); 
    ++changeCount_;
  }

  public final long getChangeCount() { return changeCount_; }
  
  private double timestampMilliseconds_;                       /**< milliseconds since 1/1/1970. -1 for none */
  private ContentType type_ = ContentType.DATA;                /**< default is ContentType.DATA. */
  private int freshnessSeconds_;                               /**< -1 for none */
  private Name.Component finalBlockID_ = new Name.Component(); /**< size 0 for none */
  private long changeCount_ = 0;
}
