/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/detail/key-impl.cpp
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

package net.named_data.jndn.security.pib.detail;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibCertificateContainer;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

/**
 * PibKeyImpl provides the backend implementation for PibKey. A PibKey has only
 * one backend instance, but may have multiple frontend handles. Each frontend
 * handle is associated with the only one backend PibKeyImpl.
 */
public class PibKeyImpl {
  /**
   * Create a PibKeyImpl with keyName. If the key does not exist in the backend
   * implementation, add it by creating it from the keyEncoding. If a key with
   * keyName already exists, overwrite it.
   * @param keyName The name of the key, which is copied.
   * @param keyEncoding The buffer of encoded key bytes, which is copied.
   * @param pibImpl The Pib backend implementation.
   */
  public PibKeyImpl(Name keyName, ByteBuffer keyEncoding, PibImpl pibImpl)
    throws PibImpl.Error
  {
    identityName_ = PibKey.extractIdentityFromKeyName(keyName);
    keyName_ = new Name(keyName);
    keyEncoding_ = new Blob(keyEncoding, true);
    certificates_ = new PibCertificateContainer(keyName, pibImpl);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    try {
      PublicKey publicKey = new PublicKey(keyEncoding_);
      keyType_ = publicKey.getKeyType();
    } catch (UnrecognizedKeyFormatException ex) {
      throw new IllegalArgumentException("Invalid key encoding");
    }

    pibImpl_.addKey(identityName_, keyName_, keyEncoding);
  }

  /**
   * Create a PibKeyImpl with keyName. Initialize the cached key encoding with
   * pibImpl.getKeyBits().
   * @param keyName The name of the key, which is copied.
   * @param pibImpl The Pib backend implementation.
   * @throws Pib.Error if the key with keyName does not exist.
   */
  public PibKeyImpl(Name keyName, PibImpl pibImpl) throws Pib.Error, PibImpl.Error
  {
    identityName_ = PibKey.extractIdentityFromKeyName(keyName);
    keyName_ = new Name(keyName);
    certificates_ = new PibCertificateContainer(keyName, pibImpl);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    keyEncoding_ = pibImpl_.getKeyBits(keyName_);

    PublicKey publicKey;
    try {
      publicKey = new PublicKey(keyEncoding_);
    } catch (UnrecognizedKeyFormatException ex) {
      // We don't expect this since we just fetched the encoding.
      throw new Pib.Error("Error decoding public key: " + ex);
    }
    keyType_ = publicKey.getKeyType();
  }

  /*
   * Get the key name.
   * @return The key name. You must not change the object. If you need to change
   * it, make a copy.
   */
  public final Name
  getName() { return keyName_; }

  /**
   * Get the name of the identity this key belongs to.
   * @return The name of the identity. You must not change the object. If you
   * need to change it, make a copy.
   */
  public final Name
  getIdentityName() { return identityName_; }

  /**
   * Get the key type.
   * @return The key type.
   */
  public final KeyType
  getKeyType() { return keyType_; }

  /**
   * Get the public key encoding.
   * @return The public key encoding.
   */
  public final Blob
  getPublicKey() { return keyEncoding_; }

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If no default
   * certificate for the key has been set, then set the added certificate as
   * default for the key.
   * @param certificate The certificate to add. This copies the object.
   * @throws IllegalArgumentException if the name of the certificate does not
   * match the key name.
   */
  public final void
  addCertificate(CertificateV2 certificate)
    throws CertificateV2.Error, PibImpl.Error
  {
    // BOOST_ASSERT(certificates_.isConsistent());
    certificates_.add(certificate);
  }

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * @param certificateName The name of the certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name.
   */
  public final void
  removeCertificate(Name certificateName) throws PibImpl.Error
  {
    // BOOST_ASSERT(certificates_.isConsistent());

    if (defaultCertificate_ != null &&
        defaultCertificate_.getName().equals(certificateName))
      defaultCertificate_ = null;

    certificates_.remove(certificateName);
  }

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the CertificateV2 object.
   * @throws IllegalArgumentException if certificateName does not match the key name.
   * @throws Pib.Error if the certificate does not exist.
   */
  public final CertificateV2
  getCertificate(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    // BOOST_ASSERT(certificates_.isConsistent());
    return certificates_.get(certificateName);
  }

  /**
   * Set the existing certificate with name certificateName as the default
   * certificate.
   * @param certificateName The name of the certificate.
   * @return The default certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name
   * @throws Pib.Error if the certificate does not exist.
   */
  public final CertificateV2
  setDefaultCertificate(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    // BOOST_ASSERT(certificates_.isConsistent());

    defaultCertificate_ = certificates_.get(certificateName);
    pibImpl_.setDefaultCertificateOfKey(keyName_, certificateName);
    return defaultCertificate_;
  }

  /**
   * Add the certificate and set it as the default certificate of the key.
   * If a certificate with the same name (without implicit digest) already
   * exists, then overwrite the certificate.
   * @param certificate The certificate to add. This copies the object.
   * @throws IllegalArgumentException if the name of the certificate does not
   * match the key name.
   * @return The default certificate.
   */
  public final CertificateV2
  setDefaultCertificate(CertificateV2 certificate)
    throws CertificateV2.Error, PibImpl.Error, Pib.Error
  {
    addCertificate(certificate);
    return setDefaultCertificate(certificate.getName());
  }

  /**
   * Get the default certificate for this Key.
   * @return A copy of the default certificate.
   * @throws Pib.Error if the default certificate does not exist.
   */
  public final CertificateV2
  getDefaultCertificate() throws Pib.Error, PibImpl.Error
  {
    // BOOST_ASSERT(certificates_.isConsistent());

    if (defaultCertificate_ == null)
      defaultCertificate_ = pibImpl_.getDefaultCertificateOfKey(keyName_);

    // BOOST_ASSERT(pibImpl_->getDefaultCertificateOfKey(keyName_)->wireEncode() == defaultCertificate_->wireEncode());

    return defaultCertificate_;
  }

  /**
   * Get the certificates_ container, which should only be used for testing.
   */
  public final PibCertificateContainer
  getCertificates_() { return certificates_; }

  private final Name identityName_;
  private final Name keyName_;
  private final Blob keyEncoding_;
  private final KeyType keyType_;

  private CertificateV2 defaultCertificate_ = null;

  private final PibCertificateContainer certificates_;

  private final PibImpl pibImpl_;
}
