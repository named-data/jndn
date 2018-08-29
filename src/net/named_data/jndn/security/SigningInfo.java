/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/signing-info.cpp
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

import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.util.Common;

/**
 * A SigningInfo holds the signing parameters passed to the KeyChain. A
 * SigningInfo is invalid if the specified identity/key/certificate does not
 * exist, or the PibIdentity or PibKey instance is not valid.
 */
public class SigningInfo {
  public static enum SignerType {
    /** No signer is specified. Use default settings or follow the trust schema. */
    NULL,
    /** The signer is an identity. Use its default key and default certificate. */
    ID,
    /** The signer is a key. Use its default certificate. */
    KEY,
    /** The signer is a certificate. Use it directly. */
    CERT,
    /** Use a SHA-256 digest. No signer needs to be specified. */
    SHA256
  }

  /**
   * Create a SigningInfo with the signerType and signerName, with other default
   * values. The digest algorithm is set to DigestAlgorithm.SHA256.
   * @param signerType The type of signer.
   * @param signerName The name of signer. The interpretation of the signerName
   * differs based on the signerType. This copies the Name.
   */
  public SigningInfo(SignerType signerType, Name signerName)
  {
    reset(signerType);
    name_ = new Name(signerName);
    digestAlgorithm_ = DigestAlgorithm.SHA256;
  }

  /**
   * Create a SigningInfo with the signerType and an empty signerName, with
   * other default values. The digest algorithm is set to DigestAlgorithm.SHA256.
   * @param signerType The type of signer.
   */
  public SigningInfo(SignerType signerType)
  {
    reset(signerType);
    digestAlgorithm_ = DigestAlgorithm.SHA256;
  }

  /**
   * Create a SigningInfo with a signerType of NULL and an empty signerName,
   * with other default values. The digest algorithm is set to
   * DigestAlgorithm.SHA256.
   */
  public SigningInfo()
  {
    reset(SignerType.NULL);
    digestAlgorithm_ = DigestAlgorithm.SHA256;
  }

  /**
   * Create a SigningInfo of type SignerType.ID according to the given
   * PibIdentity. The digest algorithm is set to DigestAlgorithm.SHA256.
   * @param identity An existing PibIdentity which is not copied, or a null
   * PibIdentity. If this is null then use the default identity, otherwise use
   * identity.getName().
   */
  public SigningInfo(PibIdentity identity)
  {
    digestAlgorithm_ = DigestAlgorithm.SHA256;
    setPibIdentity(identity);
  }

  /**
   * Create a SigningInfo of type SignerType.KEY according to the given PibKey.
   * The digest algorithm is set to DigestAlgorithm.SHA256.
   * @param key An existing PibKey which is not copied, or a null PibKey. If
   * this is null then use the default key for the identity, otherwise use
   * key.getName().
   */
  public SigningInfo(PibKey key)
  {
    digestAlgorithm_ = DigestAlgorithm.SHA256;
    setPibKey(key);
  }

  /**
   * Create a SigningInfo from its string representation.
   * The digest algorithm is set to DigestAlgorithm.SHA256.
   * @param signingString The representative signing string for the signing
   * method, as follows:
   * Default signing: "" (the empty string).
   * Signing with the default certificate of the default key for the identity
   * with the specified name:
   * `id:/my-identity`.
   * Signing with the default certificate of the key with the specified name:
   * `key:/my-identity/ksk-1`.
   * Signing with the certificate with the specified name:
   * `cert:/my-identity/KEY/ksk-1/ID-CERT/%FD%01`.
   * Signing with sha256 digest: `id:/localhost/identity/digest-sha256` (the
   * value returned by getDigestSha256Identity()).
   * @throws IllegalArgumentException if the signingString format is invalid.
   */
  public SigningInfo(String signingString)
  {
    reset(SignerType.NULL);
    digestAlgorithm_ = DigestAlgorithm.SHA256;

    if (signingString.equals(""))
      return;

    int iColon = signingString.indexOf(':');
    if (iColon < 0)
      throw new IllegalArgumentException
        ("Invalid signing string cannot represent SigningInfo");

    String scheme = signingString.substring(0, iColon);
    String nameArg = signingString.substring(iColon + 1);

    if (scheme.equals("id")) {
      if (nameArg.equals(getDigestSha256Identity().toUri()))
        setSha256Signing();
      else
        setSigningIdentity(new Name(nameArg));
    }
    else if (scheme.equals("key"))
      setSigningKeyName(new Name(nameArg));
    else if (scheme.equals("cert"))
      setSigningCertificateName(new Name(nameArg));
    else
      throw new IllegalArgumentException("Invalid signing string scheme");
  }

  /**
   * Create a SigningInfo as a copy of the given signingInfo. (This takes a
   * pointer to the given signingInfo PibIdentity and PibKey without copying.)
   * @param signingInfo The SigningInfo to copy.
   */
  public SigningInfo(SigningInfo signingInfo)
  {
    type_ = signingInfo.type_;
    name_ = new Name(signingInfo.name_);
    identity_ = signingInfo.identity_;
    key_ = signingInfo.key_;
    digestAlgorithm_ = signingInfo.digestAlgorithm_;
    validityPeriod_ = new ValidityPeriod(signingInfo.validityPeriod_);
  }

  /**
   * Set this to type SignerType.ID and an identity with name identityName.
   * This does not change the digest algorithm.
   * @param identityName The name of the identity. This copies the Name.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setSigningIdentity(Name identityName)
  {
    reset(SignerType.ID);
    name_ = new Name(identityName);
    return this;
  }

  /**
   * Set this to type SignerType.KEY and a key with name keyName.
   * This does not change the digest algorithm.
   * @param keyName The name of the key. This copies the Name.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setSigningKeyName(Name keyName)
  {
    reset(SignerType.KEY);
    name_ = new Name(keyName);
    return this;
  }

  /**
   * Set this to type SignerType.CERT and a certificate with name
   * certificateName. This does not change the digest algorithm.
   * @param certificateName The name of the certificate. This copies the Name.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setSigningCertificateName(Name certificateName)
  {
    reset(SignerType.CERT);
    name_ = new Name(certificateName);
    return this;
  }

  /**
   * Set this to type SignerType.SHA256, and set the digest algorithm to
   * DigestAlgorithm.SHA256.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setSha256Signing()
  {
    reset(SignerType.SHA256);
    digestAlgorithm_ = DigestAlgorithm.SHA256;
    return this;
  }

  /**
   * Set this to type SignerType.ID according to the given PibIdentity.
   * This does not change the digest algorithm.
   * @param identity An existing PibIdentity which is not copied, or a null
   * PibIdentity. If this is null then use the default identity, otherwise use
   * identity.getName().
   * @return This SigningInfo.
   */
  public final SigningInfo
  setPibIdentity(PibIdentity identity)
  {
    reset(SignerType.ID);
    if (identity != null)
      name_ = identity.getName();
    identity_ = identity;
    return this;
  }

  /**
   * Set this to type SignerType.KEY according to the given PibKey.
   * This does not change the digest algorithm.
   * @param key An existing PibKey which is not copied, or a null PibKey. If
   * this is null then use the default key for the identity, otherwise use
   * key.getName().
   * @return This SigningInfo.
   */
  public final SigningInfo
  setPibKey(PibKey key)
  {
    reset(SignerType.KEY);
    if (key != null)
      name_ = key.getName();
    key_ = key;
    return this;
  }

  /**
   * Get the type of the signer.
   * @return The type of the signer
   */
  public final SignerType
  getSignerType() { return type_; }

  /**
   * Get the name of signer.
   * @return The name of signer. The interpretation differs based on the
   * signerType.
   */
  public final Name
  getSignerName() { return name_; }

  /**
   * Get the PibIdentity of the signer.
   * @return The PibIdentity handler of the signer, or null if getSignerName()
   * should be used to find the identity.
   * @throws AssertionError if the signer type is not SignerType.ID.
   */
  public final PibIdentity
  getPibIdentity()
  {
    if (type_ != SignerType.ID)
      throw new AssertionError
        ("getPibIdentity: The signer type is not SignerType.ID");
    return identity_;
  }

  /**
   * Get the PibKey of the signer.
   * @return The PibKey handler of the signer, or null if getSignerName() should
   * be used to find the key.
   * @throws AssertionError if the signer type is not SignerType.KEY.
   */
  public final PibKey
  getPibKey()
  {
    if (type_ != SignerType.KEY)
      throw new AssertionError
        ("getPibKey: The signer type is not SignerType.KEY");
    return key_;
  }

  /**
   * Set the digest algorithm for public key operations.
   * @param digestAlgorithm The digest algorithm.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setDigestAlgorithm(DigestAlgorithm digestAlgorithm)
  {
    digestAlgorithm_ = digestAlgorithm;
    return this;
  }

  /**
   * Get the digest algorithm for public key operations.
   * @return The digest algorithm.
   */
  public final DigestAlgorithm
  getDigestAlgorithm() { return digestAlgorithm_; }

  /**
   * Set the validity period for the signature info.
   * Note that the equivalent ndn-cxx method uses a semi-prepared SignatureInfo,
   * but this method only uses the ValidityPeriod from the SignatureInfo.
   * @param validityPeriod The validity period, which is copied.
   * @return This SigningInfo.
   */
  public final SigningInfo
  setValidityPeriod(ValidityPeriod validityPeriod)
  {
    validityPeriod_ = new ValidityPeriod(validityPeriod);
    return this;
  }

  /**
   * Get the validity period for the signature info.
   * Note that the equivalent ndn-cxx method uses a semi-prepared SignatureInfo,
   * but this method only uses the ValidityPeriod from the SignatureInfo.
   * @return The validity period.
   */
  public final ValidityPeriod
  getValidityPeriod() { return validityPeriod_; }

  /**
   * Get the string representation of this SigningInfo.
   * @return The string representation.
   */
  public String
  toString()
  {
    if (type_ == SignerType.NULL)
      return "";
    else if (type_ == SignerType.ID)
      return "id:" + getSignerName().toUri();
    else if (type_ == SignerType.KEY)
      return "key:" + getSignerName().toUri();
    else if (type_ == SignerType.CERT)
      return "cert:" + getSignerName().toUri();
    else if (type_ == SignerType.SHA256)
      return "id:" + getDigestSha256Identity().toUri();
    else
      // We don't expect this to happen.
      throw new AssertionError("Unknown signer type");
  }

  /**
   * Get the localhost identity which indicates that the signature is generated
   * using SHA-256.
   * @return A new Name of the SHA-256 identity.
   */
  public static Name
  getDigestSha256Identity()
  {
    return new Name("/localhost/identity/digest-sha256");
  }

  /**
   * Check and set the signerType, and set others to default values. This does
   * NOT reset the digest algorithm.
   * @param signerType The The type of signer.
   */
  private void
  reset(SignerType signerType)
  {
    if (!(signerType == SignerType.NULL ||
          signerType == SignerType.ID ||
          signerType == SignerType.KEY ||
          signerType == SignerType.CERT ||
          signerType == SignerType.SHA256))
      throw new AssertionError("SigningInfo: The signerType is not valid");

    type_ = signerType;
    name_ = new Name();
    identity_ = null;
    key_ = null;
    validityPeriod_ = new ValidityPeriod();
  }

  private SignerType type_;
  private Name name_;
  private PibIdentity identity_;
  private PibKey key_;
  private DigestAlgorithm digestAlgorithm_;
  private ValidityPeriod validityPeriod_ = new ValidityPeriod();

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
