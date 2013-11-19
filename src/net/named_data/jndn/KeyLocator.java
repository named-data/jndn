/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

public class KeyLocator {
  /**
   * Create a new KeyLocator with fields set to NONE.
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
      keyName_ = new Name(keyLocator.keyName_);
    keyNameType_ = keyLocator.keyNameType_;
  }
  
  public enum KeyLocatorType {
    NONE, KEY, CERTIFICATE, KEYNAME
  }
  
  public enum KeyNameType {
    NONE, PUBLISHER_PUBLIC_KEY_DIGEST, PUBLISHER_CERTIFICATE_DIGEST, PUBLISHER_ISSUER_KEY_DIGEST, PUBLISHER_ISSUER_CERTIFICATE_DIGEST
  }

  /**
   * Return a deep copy of this KeyLocator.
   * @return A new KeyLocator.
   * @throws CloneNotSupportedException 
   */
  @Override
  public Object
  clone() throws CloneNotSupportedException
  {
    return new KeyLocator(this);
  }
  
  public KeyLocatorType 
  getType() { return type_; }
  
  public Blob 
  getKeyData() { return keyData_; }

  public Name
  getKeyName() { return keyName_; }
  
  public KeyNameType 
  getKeyNameType() { return keyNameType_; }

  public void 
  setType(KeyLocatorType type) { type_ = type; }
    
  public void 
  setKeyData(Blob keyData) { keyData_ = (keyData == null ? new Blob() : keyData_); }

  public void 
  setKeyName(Name keyName) { keyName_ = (keyName == null ? new Name() : keyName); }
  
  public void 
  setKeyNameType(KeyNameType keyNameType) { keyNameType_ = keyNameType; }

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
  private KeyNameType keyNameType_ = KeyNameType.NONE; /**< The type of data for keyName_. (only used if type_ is KeyLocatorType.KEYNAME.) */
}
