/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

public class KeyLocator {
  /**
   * Create a new KeyLocator with default values.
   */
  public KeyLocator()
  {
    keyNameChangeCount_ = keyName_.getChangeCount();
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
      keyName_ = new Name(keyLocator.keyName_);
    keyNameType_ = keyLocator.keyNameType_;
    keyNameChangeCount_ = keyName_.getChangeCount();
  }
  
  public enum KeyLocatorType {
    NONE, KEY, CERTIFICATE, KEYNAME
  }
  
  public enum KeyNameType {
    NONE, PUBLISHER_PUBLIC_KEY_DIGEST, PUBLISHER_CERTIFICATE_DIGEST, PUBLISHER_ISSUER_KEY_DIGEST, PUBLISHER_ISSUER_CERTIFICATE_DIGEST
  }

  public final KeyLocatorType 
  getType() { return type_; }
  
  public final Blob 
  getKeyData() { return keyData_; }

  public final Name
  getKeyName() { return keyName_; }
  
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
    keyName_ = (keyName == null ? new Name() : keyName);
    keyNameChangeCount_ = keyName_.getChangeCount();
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
    keyName_ = new Name();
    keyNameType_ = KeyNameType.NONE;
    keyNameChangeCount_ = keyName_.getChangeCount();
    ++changeCount_;
  }

  public long getChangeCount()
  {
    if (keyNameChangeCount_ != keyName_.getChangeCount()) {
      ++changeCount_;
      keyNameChangeCount_ = keyName_.getChangeCount();
    }
    
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
  private Name keyName_ = new Name();                  /**< The key name (only used if type_ KeyLocatorType.KEYNAME.) */
  private long keyNameChangeCount_;
  private KeyNameType keyNameType_ = KeyNameType.NONE; /**< The type of data for keyName_. (only used if type_ is KeyLocatorType.KEYNAME.) */
  private long changeCount_ = 0;
}
