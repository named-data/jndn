/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate.hpp
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

package net.named_data.jndn.security.v2;

import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encrypt.Schedule;
import net.named_data.jndn.security.ValidityPeriod;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * CertificateV2 represents a certificate following the certificate format
 * naming convention.
 *
 * Overview of the NDN certificate format:
 *
 *     CertificateV2 ::= DATA-TLV TLV-LENGTH
 *                         Name      (= /{NameSpace}/KEY/[KeyId]/[IssuerId]/[Version])
 *                         MetaInfo  (.ContentType = KEY)
 *                         Content   (= X509PublicKeyContent)
 *                         SignatureInfo (= CertificateV2SignatureInfo)
 *                         SignatureValue
 *
 *     X509PublicKeyContent ::= CONTENT-TLV TLV-LENGTH
 *                                BYTE+ (= public key bits in PKCS#8 format)
 *
 *     CertificateV2SignatureInfo ::= SIGNATURE-INFO-TYPE TLV-LENGTH
 *                                      SignatureType
 *                                      KeyLocator
 *                                      ValidityPeriod
 *                                      ... optional critical or non-critical extension blocks ...
 *
 * An example of NDN certificate name:
 *
 *     /edu/ucla/cs/yingdi/KEY/%03%CD...%F1/%9F%D3...%B7/%FD%d2...%8E
 *     \_________________/    \___________/ \___________/\___________/
 *    Certificate Namespace      Key Id       Issuer Id     Version
 *         (Identity)
 *     \__________________________________/
 *                   Key Name
 *
 * Notes:
 *
 * - `Key Id` is an opaque name component to identify the instance of the public
 *   key for the certificate namespace. The value of `Key ID` is controlled by
 *   the namespace owner. The library includes helpers for generating key IDs
 *   using an 8-byte random number, SHA-256 digest of the public key, timestamp,
 *   and the specified numerical identifiers.
 *
 * - `Issuer Id` is sn opaque name component to identify the issuer of the
 *   certificate. The value is controlled by the issuer. The library includes
 *   helpers to set issuer the ID to an 8-byte random number, SHA-256 digest of
 *   the issuer's public key, and the specified numerical identifiers.
 *
 * - `Key Name` is a logical name of the key used for management purposes. the
 *    Key Name includes the certificate namespace, keyword `KEY`, and `KeyId`
 *    components.
 *
 * See https://github.com/named-data/ndn-cxx/blob/master/docs/specs/certificate-format.rst
 */
public class CertificateV2 extends Data {
  /**
   * A CertificateV2.Error extends Exception and represents errors for not
   * complying with the certificate format.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Create a CertificateV2 with content type KEY and default or unspecified
   * values.
   */
  public CertificateV2()
  {
    getMetaInfo().setType(ContentType.KEY);
  }

  /**
   * Create a CertificateV2 from the content in the Data packet.
   * @param data The data packet with the content to copy.
   * @throws CertificateV2.Error If data does not follow the certificate format.
   */
  public CertificateV2(Data data) throws Error
  {
    // Use the copy constructor.  It clones the signature object.
    super(data);

    checkFormat();
  }

  private void
  checkFormat() throws Error
  {
    if (!isValidName(getName()))
      throw new Error
        ("The Data Name does not follow the certificate naming convention");

    if (getMetaInfo().getType() != ContentType.KEY)
      throw new Error("The Data ContentType is not KEY");

    if (getMetaInfo().getFreshnessPeriod() < 0.0)
      throw new Error("The Data FreshnessPeriod is not set");

    if (getContent().size() == 0)
      throw new Error("The Data Content is empty");
  }

  /**
   * Get key name from the certificate name.
   * @return The key name as a new Name.
   */
  public final Name
  getKeyName() { return getName().getPrefix(KEY_ID_OFFSET + 1); }

  /**
   * Get the identity name from the certificate name.
   * @return The identity name as a new Name.
   */
  public final Name
  getIdentity() { return getName().getPrefix(KEY_COMPONENT_OFFSET); }

  /**
   * Get the key ID component from the certificate name.
   * @return The key ID name component.
   */
  public final Name.Component
  getKeyId() { return getName().get(KEY_ID_OFFSET); }

  /**
   * Get the issuer ID component from the certificate name.
   * @return The issuer ID component.
   */
  public final Name.Component
  getIssuerId() { return getName().get(ISSUER_ID_OFFSET); }

  /**
   * Get the public key DER encoding.
   * @return The DER encoding Blob.
   * @throws CertificateV2.Error If the public key is not set.
   */
  public final Blob
  getPublicKey() throws Error
  {
    if (getContent().size() == 0)
      throw new Error("The public key is not set (the Data content is empty)");

    return getContent();
  }

  /**
   * Get the certificate validity period from the SignatureInfo.
   * @return The ValidityPeriod object.
   * @throws IllegalArgumentException If the SignatureInfo doesn't have a
   * ValidityPeriod.
   */
  public final ValidityPeriod
  getValidityPeriod()
  {
    if (!ValidityPeriod.canGetFromSignature(getSignature()))
      throw new IllegalArgumentException
        ("The SignatureInfo does not have a ValidityPeriod");

    return ValidityPeriod.getFromSignature(getSignature());
  }

  /**
   * Check if the time falls within the validity period.
   * @param time The time to check as milliseconds since Jan 1, 1970 UTC.
   * @return True if the beginning of the validity period is less than or equal
   * to time and time is less than or equal to the end of the validity period.
   * @throws IllegalArgumentException If the SignatureInfo doesn't have a
   * ValidityPeriod.
   */
  public final boolean
  isValid(double time) { return getValidityPeriod().isValid(time); }

  /**
   * Check if the current time falls within the validity period.
   * @return True if the beginning of the validity period is less than or equal
   * to the current time and the current time is less than or equal to the end
   * of the validity period.
   * @throws IllegalArgumentException If the SignatureInfo doesn't have a
   * ValidityPeriod.
   */
  public final boolean
  isValid() { return getValidityPeriod().isValid(); }

  // TODO: getExtension

  /**
   * Write a string representation of this certificate to result.
   * @param result The StringBuffer to write to.
   */
  public void
  printCertificate(StringBuffer result)
  {
    result.append("Certificate name:\n");
    result.append("  ").append(getName().toUri()).append("\n");
    result.append("Validity:\n");
    result.append("  NotBefore: ").append(Schedule.toIsoString
      (getValidityPeriod().getNotBefore())).append("\n");
    result.append("  NotAfter: ").append(Schedule.toIsoString
      (getValidityPeriod().getNotAfter())).append("\n");

    // TODO: Print the extension.

    result.append("Public key bits:\n");
    try {
      result.append(Common.base64Encode(getPublicKey().getImmutableArray(), true));
    } catch (Error ex) {
      // No public key.
    }

    result.append("Signature Information:\n");
    result.append("  Signature Type: ");
    if (getSignature() instanceof Sha256WithEcdsaSignature)
      result.append("SignatureSha256WithEcdsa\n");
    else if (getSignature() instanceof Sha256WithRsaSignature)
      result.append("SignatureSha256WithRsa\n");
    else
      result.append("<unknown>\n");

    if (KeyLocator.canGetFromSignature(getSignature())) {
      result.append("  Key Locator: ");
      KeyLocator keyLocator = KeyLocator.getFromSignature(getSignature());
      if (keyLocator.getType() == KeyLocatorType.KEYNAME) {
        if (keyLocator.getKeyName().equals(getKeyName()))
          result.append("Self-Signed ");

        result.append("Name=").append(keyLocator.getKeyName().toUri()).append("\n");
      }
      else
        result.append("<no KeyLocator key name>\n");
    }
  }

  /**
   * Override to call the base class wireDecode then check the certificate
   * format.
   * @param input The input byte array to be decoded as an immutable Blob.
   * @param wireFormat A WireFormat object used to decode the input.
   */
  public void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    super.wireDecode(input, wireFormat);
    try {
      checkFormat();
    } catch (Error ex) {
      throw new EncodingException(ex.getMessage());
    }
  }

  /**
   * Use printCertificate to return a string representation of this certificate.
   * @return The string representation of this certificate.
   */
  public String
  toString()
  {
    StringBuffer result = new StringBuffer();
    printCertificate(result);
    return result.toString();
  }

  /**
   * Check if certificateName follows the naming convention for a certificate.
   * @param certificateName The name of the certificate.
   * @return True if certificateName follows the naming convention.
   */
  public static boolean
  isValidName(Name certificateName)
  {
    // /{NameSpace}/KEY/[KeyId]/[IssuerId]/[Version]
    return (certificateName.size() >= MIN_CERT_NAME_LENGTH &&
            certificateName.get(KEY_COMPONENT_OFFSET).equals(KEY_COMPONENT));
  }

  /**
   * Extract the identity namespace from certificateName.
   * @param certificateName The name of the certificate.
   * @return The identity namespace as a new Name.
   */
  public static Name
  extractIdentityFromCertName(Name certificateName)
  {
    if (!isValidName(certificateName))
      throw new IllegalArgumentException
        ("Certificate name `" + certificateName.toUri() +
          "` does not follow the naming conventions");

    return certificateName.getPrefix(KEY_COMPONENT_OFFSET);
  }

  /**
   * Extract key name from certificateName.
   * @param certificateName The name of the certificate.
   * @return The key name as a new Name.
   */
  public static Name
  extractKeyNameFromCertName(Name certificateName)
  {
    if (!isValidName(certificateName)) {
      throw new IllegalArgumentException
        ("Certificate name `" + certificateName.toUri() +
          "` does not follow the naming conventions");
    }

    // Trim everything after the key ID.
    return certificateName.getPrefix(KEY_ID_OFFSET + 1);
  }

  public static final int VERSION_OFFSET = -1;
  public static final int ISSUER_ID_OFFSET = -2;
  public static final int KEY_ID_OFFSET = -3;
  public static final int KEY_COMPONENT_OFFSET = -4;
  public static final int MIN_CERT_NAME_LENGTH = 4;
  public static final int MIN_KEY_NAME_LENGTH = 2;
  public static final Name.Component KEY_COMPONENT = new Name.Component("KEY");
}
