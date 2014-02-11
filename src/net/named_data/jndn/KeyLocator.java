/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.util.ChangeCounter;

public class KeyLocator implements ChangeCountable {
  /**
   * Create a new KeyLocator with default values.
   */
  public KeyLocator()
  {
  }

  /**
   * Create a new KeyLocator with a copy of the fields in keyLocator.
   * @param keyLocator The KeyLocator to copy.
   */
  public KeyLocator(KeyLocator keyLocator)
  {
    type_ = keyLocator.type_;
    keyData_ = keyLocator.keyData_;
    if (keyLocator.keyName_ != null)
      keyName_.set(new Name(keyLocator.keyName_.get()));
    keyNameType_ = keyLocator.keyNameType_;
  }
    
  public final KeyLocatorType 
  getType() { return type_; }
  
  public final Blob 
  getKeyData() { return keyData_; }

  public final Name
  getKeyName() { return keyName_.get(); }
  
  public final KeyNameType 
  getKeyNameType() { return keyNameType_; }

  public final void 
  setType(KeyLocatorType type) 
  { 
    type_ = type; 
    ++changeCount_;
  }
    
  public final void 
  setKeyData(Blob keyData) 
  { 
    keyData_ = (keyData == null ? new Blob() : keyData_); 
    ++changeCount_;
  }

  public final void 
  setKeyName(Name keyName) 
  { 
    keyName_.set((keyName == null ? new Name() : keyName));
    ++changeCount_;
  }
  
  public final void 
  setKeyNameType(KeyNameType keyNameType) 
  { 
    keyNameType_ = keyNameType; 
    ++changeCount_;
  }

  /**
   * Clear fields and reset to default values.
   */
  public final void 
  clear()
  {
    type_ = KeyLocatorType.NONE;
    keyData_ = new Blob();
    keyName_.set(new Name());
    keyNameType_ = KeyNameType.NONE;
    ++changeCount_;
  }

  /**
   * Get the change count, which is incremented each time this object 
   * (or a child object) is changed.
   * @return The change count.
   */
  @Override
  public final long 
  getChangeCount()
  {
    if (keyName_.checkChanged())
      // A child object has changed, so update the change count.
      ++changeCount_;
    
    return changeCount_;    
  }
  
  private KeyLocatorType type_ = KeyLocatorType.NONE;
  private Blob keyData_ = new Blob(); /**< A Blob for the key data as follows:
    *   If type_ is KeyLocatorType.KEY, the key data.
    *   If type_ is KeyLocatorType.CERTIFICATE, the certificate data. 
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_PUBLIC_KEY_DIGEST, the publisher public key digest. 
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_CERTIFICATE_DIGEST, the publisher certificate digest. 
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_ISSUER_KEY_DIGEST, the publisher issuer key digest. 
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_ISSUER_CERTIFICATE_DIGEST, the publisher issuer certificate digest. 
    */
  private final ChangeCounter<Name> keyName_ = 
    new ChangeCounter<Name>(new Name()); /**< The key name (only used if
                                              type_ KeyLocatorType.KEYNAME.) */
  private KeyNameType keyNameType_ =
    KeyNameType.NONE; /**< The type of data for keyName_. (only used if
                           type_ is KeyLocatorType.KEYNAME.) */
  private long changeCount_ = 0;
}
