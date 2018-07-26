/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/safe-bag.cpp
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

package net.named_data.jndn.security;

import java.nio.ByteBuffer;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.tpm.TpmBackEndMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.SignedBlob;

/**
 * A SafeBag represents a container for sensitive related information such as a
 * certificate and private key.
 */
public class SafeBag {
  /**
   * Create a SafeBag with the given certificate and private key.
   * @param certificate The certificate data packet. This copies the object.
   * @param privateKeyBag The encoded private key. If encrypted, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
   * PKCS #8 PrivateKeyInfo.
   */
  public SafeBag(Data certificate, Blob privateKeyBag)
  {
    certificate_ = new Data(certificate);
    privateKeyBag_ = privateKeyBag;
  }

  /**
   * Create a SafeBag with given private key and a new self-signed certificate
   * for the given public key.
   * @param keyName The name of the public key. The certificate name will be
   * {keyName}/self/{version} where the version is based on the current time.
   * This copies the Name.
   * @param privateKeyBag The encoded private key. If encrypted, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
   * PKCS #8 PrivateKeyInfo.
   * @param publicKeyEncoding The encoded public key for the certificate.
   * @param password The password for decrypting the private key in order to
   * sign the self-signed certificate. If the password is used to decrypt the
   * PKCS #8 EncryptedPrivateKeyInfo.
   * @param digestAlgorithm The digest algorithm for signing the self-signed
   * certificate.
   * @param wireFormat A WireFormat object used to encode the self-signed
   * certificate in order to sign it.
   */
  public SafeBag
    (Name keyName, Blob privateKeyBag, Blob publicKeyEncoding,
     ByteBuffer password, DigestAlgorithm digestAlgorithm, WireFormat wireFormat)
    throws TpmBackEnd.Error, Pib.Error
  {
    certificate_ = makeSelfSignedCertificate
      (keyName, privateKeyBag, publicKeyEncoding, password, digestAlgorithm,
       wireFormat);
    privateKeyBag_ = privateKeyBag;
  }

  /**
   * Create a SafeBag with given private key and a new self-signed certificate
   * for the given public key.
   * Use getDefaultWireFormat() to encode the self-signed certificate in order
   * to sign it.
   * @param keyName The name of the public key. The certificate name will be
   * {keyName}/self/{version} where the version is based on the current time.
   * This copies the Name.
   * @param privateKeyBag The encoded private key. If encrypted, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
   * PKCS #8 PrivateKeyInfo.
   * @param publicKeyEncoding The encoded public key for the certificate.
   * @param password The password for decrypting the private key in order to
   * sign the self-signed certificate. If the password is used to decrypt the
   * PKCS #8 EncryptedPrivateKeyInfo.
   * @param digestAlgorithm The digest algorithm for signing the self-signed
   * certificate.
   */
  public SafeBag
    (Name keyName, Blob privateKeyBag, Blob publicKeyEncoding,
     ByteBuffer password, DigestAlgorithm digestAlgorithm)
    throws TpmBackEnd.Error, Pib.Error
  {
    certificate_ = makeSelfSignedCertificate
      (keyName, privateKeyBag, publicKeyEncoding, password, digestAlgorithm,
       WireFormat.getDefaultWireFormat());
    privateKeyBag_ = privateKeyBag;
  }

  /**
   * Create a SafeBag with given private key and a new self-signed certificate
   * for the given public key, using DigestAlgorithm.SHA256 to sign it.
   * Use getDefaultWireFormat() to encode the self-signed certificate in order
   * to sign it.
   * @param keyName The name of the public key. The certificate name will be
   * {keyName}/self/{version} where the version is based on the current time.
   * This copies the Name.
   * @param privateKeyBag The encoded private key. If encrypted, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
   * PKCS #8 PrivateKeyInfo.
   * @param publicKeyEncoding The encoded public key for the certificate.
   * @param password The password for decrypting the private key in order to
   * sign the self-signed certificate. If the password is used to decrypt the
   * PKCS #8 EncryptedPrivateKeyInfo.
   */
  public SafeBag
    (Name keyName, Blob privateKeyBag, Blob publicKeyEncoding,
     ByteBuffer password)
    throws TpmBackEnd.Error, Pib.Error
  {
    certificate_ = makeSelfSignedCertificate
      (keyName, privateKeyBag, publicKeyEncoding, password, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
    privateKeyBag_ = privateKeyBag;
  }

  /**
   * Create a SafeBag with given private key and a new self-signed certificate
   * for the given public key, using DigestAlgorithm.SHA256 to sign it.
   * Use getDefaultWireFormat() to encode the self-signed certificate in order
   * to sign it.
   * @param keyName The name of the public key. The certificate name will be
   * {keyName}/self/{version} where the version is based on the current time.
   * This copies the Name.
   * @param privateKeyBag The encoded private key, as an unencrypted PKCS #8
   * PrivateKeyInfo.
   * @param publicKeyEncoding The encoded public key for the certificate.
   */
  public SafeBag(Name keyName, Blob privateKeyBag, Blob publicKeyEncoding)
    throws TpmBackEnd.Error, Pib.Error
  {
    certificate_ = makeSelfSignedCertificate
      (keyName, privateKeyBag, publicKeyEncoding, null, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
    privateKeyBag_ = privateKeyBag;
  }

  /**
   * Get the certificate data packet.
   * @return The certificate as a Data packet. If you need to process it as a
   * certificate object then you must create a new CertificateV2(data).
   */
  public final Data getCertificate() { return certificate_; }

  /**
   * Get the encoded private key.
   * @return The encoded private key. If encrypted, this is a PKCS #8
   * EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted PKCS #8
   * PrivateKeyInfo.
   */
  public final Blob getPrivateKeyBag() { return privateKeyBag_; }

  private static CertificateV2
  makeSelfSignedCertificate
    (Name keyName, Blob privateKeyBag, Blob publicKeyEncoding,
     ByteBuffer password, DigestAlgorithm digestAlgorithm, WireFormat wireFormat)
    throws TpmBackEnd.Error, Pib.Error
  {
    CertificateV2 certificate = new CertificateV2();

    // Set the name.
    double now = Common.getNowMilliseconds();
    Name certificateName = new Name(keyName);
    certificateName.append("self").appendVersion((long)now);
    certificate.setName(certificateName);

    // Set the MetaInfo.
    certificate.getMetaInfo().setType(ContentType.KEY);
    // Set a one-hour freshness period.
    certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

    // Set the content.
    PublicKey publicKey = null;
    try {
      publicKey = new PublicKey(publicKeyEncoding);
    } catch (UnrecognizedKeyFormatException ex) {
      // Promote to Pib.Error.
      throw new Pib.Error("Error decoding public key " + ex);
    }
    certificate.setContent(publicKey.getKeyDer());

    // Create a temporary in-memory Tpm and import the private key.
    Tpm tpm = new Tpm("", "", new TpmBackEndMemory());
    tpm.importPrivateKey_(keyName, privateKeyBag.buf(), password);

    // Set the signature info.
    if (publicKey.getKeyType() == KeyType.RSA)
      certificate.setSignature(new Sha256WithRsaSignature());
    else if (publicKey.getKeyType() == KeyType.EC)
      certificate.setSignature(new Sha256WithEcdsaSignature());
    else
      throw new AssertionError("Unsupported key type");
    Signature signatureInfo = certificate.getSignature();
    KeyLocator.getFromSignature(signatureInfo).setType(KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(signatureInfo).setKeyName(keyName);

    // Set a 20-year validity period.
    ValidityPeriod.getFromSignature(signatureInfo).setPeriod
      (now, now + 20 * 365 * 24 * 3600 * 1000.0);

    // Encode once to get the signed portion.
    SignedBlob encoding = certificate.wireEncode(wireFormat);
    Blob signatureBytes = tpm.sign(encoding.signedBuf(), keyName, digestAlgorithm);
    signatureInfo.setSignature(signatureBytes);

    // Encode again to include the signature.
    certificate.wireEncode(wireFormat);

    return certificate;
  }

  private Data certificate_ = null;
  private Blob privateKeyBag_ = new Blob();
}
