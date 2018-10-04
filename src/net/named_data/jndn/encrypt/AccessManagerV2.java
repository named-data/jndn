/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/access-manager.cpp
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

package net.named_data.jndn.encrypt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SafeBag;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;

/**
 * AccessManagerV2 controls the decryption policy by publishing granular
 * per-namespace access policies in the form of key encryption
 * (KEK, plaintext public) and key decryption (KDK, encrypted private key)
 * key pairs. This works with EncryptorV2 and DecryptorV2 using security v2.
 * For the meaning of "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 */
public class AccessManagerV2 {
  /**
   * Create an AccessManagerV2 to serve the NAC public key for other data
   * producers to fetch, and to serve encrypted versions of the private keys
   * (as safe bags) for authorized consumers to fetch.
   *
   * KEK and KDK naming:
   *
   * [identity]/NAC/[dataset]/KEK            /[key-id]                           (== KEK, public key)
   *
   * [identity]/NAC/[dataset]/KDK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== KDK, encrypted private key)
   *
   * \_____________  ______________/
   *               \/
   *      registered with NFD
   *
   * @param identity The data owner's namespace identity. (This will be used to
   * sign the KEK and KDK.)
   * @param dataset The name of dataset that this manager is controlling.
   * @param keyChain The KeyChain used to sign Data packets.
   * @param face The Face for calling registerPrefix that will be used to
   * publish the KEK and KDK Data packets.
   */
  public AccessManagerV2
    (PibIdentity identity, Name dataset, KeyChain keyChain, Face face)
    throws Tpm.Error, TpmBackEnd.Error, PibImpl.Error, Pib.Error, KeyChain.Error,
      EncodingException, IOException, SecurityException
  {
    identity_ = identity;
    keyChain_ = keyChain;
    face_ = face;

    // The NAC identity is: <identity>/NAC/<dataset>
    // Generate the NAC key.
    PibIdentity nacIdentity = keyChain_.createIdentityV2
      (new Name(identity.getName())
       .append(EncryptorV2.NAME_COMPONENT_NAC).append(dataset),
       new RsaKeyParams());
    nacKey_ = nacIdentity.getDefaultKey();
    if (nacKey_.getKeyType() != KeyType.RSA) {
      logger_.log(Level.INFO,
        "Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating");
      nacKey_ = keyChain_.createKey(nacIdentity, new RsaKeyParams());
    }
    Name.Component nacKeyId = nacKey_.getName().get(-1);

    Name kekPrefix = new Name(nacKey_.getIdentityName())
      .append(EncryptorV2.NAME_COMPONENT_KEK);

    Data kekData = new Data(nacKey_.getDefaultCertificate());
    kekData.setName(new Name(kekPrefix).append(nacKeyId));
    kekData.getMetaInfo().setFreshnessPeriod(DEFAULT_KEK_FRESHNESS_PERIOD_MS);
    keyChain_.sign(kekData, new SigningInfo(identity_));
    // A KEK looks like a certificate, but doesn't have a ValidityPeriod.
    storage_.insert(kekData);

    OnInterestCallback serveFromStorage = new OnInterestCallback() {
      public void onInterest
        (Name prefix, Interest interest, Face face, long interestFilterId,
         InterestFilter filter) {
        Data data = storage_.find(interest);
        if (data != null) {
          logger_.log(Level.INFO, "Serving {0} from in-memory-storage",
            data.getName());
          try {
            face.putData(data);
          } catch (Throwable ex) {
            logger_.log(Level.SEVERE, "AccessManagerV2: Error in Face.putData", ex);
          }
        }
        else {
          logger_.log(Level.INFO, "Didn't find data for {0}", interest.getName());
          // TODO: Send NACK?
        }
      }
    };

    OnRegisterFailed onRegisterFailed = new OnRegisterFailed() {
      public void onRegisterFailed(Name prefix) {
        logger_.log(Level.SEVERE,
          "AccessManagerV2: Failed to register prefix {0}", prefix.toUri());
      }
    };

    kekRegisteredPrefixId_ = face_.registerPrefix
      (kekPrefix, serveFromStorage, onRegisterFailed);

    Name kdkPrefix = new Name(nacKey_.getIdentityName())
      .append(EncryptorV2.NAME_COMPONENT_KDK).append(nacKeyId);
    kdkRegisteredPrefixId_ = face_.registerPrefix
      (kdkPrefix, serveFromStorage, onRegisterFailed);
  }

  public final void
  shutdown()
  {
    face_.unsetInterestFilter(kekRegisteredPrefixId_);
    face_.unsetInterestFilter(kdkRegisteredPrefixId_);
  }

  /**
   * Authorize a member identified by memberCertificate to decrypt data under
   * the policy.
   * @param memberCertificate The certificate that identifies the member to
   * authorize.
   * @return The published KDK Data packet.
   */
  public final Data
  addMember(CertificateV2 memberCertificate)
    throws Pib.Error, PibImpl.Error, UnrecognizedKeyFormatException,
      EncodingException, TpmBackEnd.Error, KeyChain.Error,
      InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
      CertificateV2.Error
  {
    Name kdkName = new Name(nacKey_.getIdentityName());
    kdkName
      .append(EncryptorV2.NAME_COMPONENT_KDK)
      .append(nacKey_.getName().get(-1)) // key-id
      .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
      .append(memberCertificate.getKeyName());

    final int secretLength = 32;
    byte[] secret = new byte[secretLength];
    Common.getRandom().nextBytes(secret);
    // To be compatible with OpenSSL which uses a null-terminated string,
    // replace each 0 with 1. And to be compatible with the Java security
    // library which interprets the secret as a char array converted to UTF8,
    // limit each byte to the ASCII range 1 to 127.
    for (int i = 0; i < secretLength; ++i) {
      if (secret[i] == 0)
        secret[i] = 1;

      secret[i] &= 0x7f;
    }

    SafeBag kdkSafeBag = keyChain_.exportSafeBag
      (nacKey_.getDefaultCertificate(), ByteBuffer.wrap(secret));

    PublicKey memberKey = new PublicKey(memberCertificate.getPublicKey());

    EncryptedContent encryptedContent = new EncryptedContent();
    encryptedContent.setPayload(kdkSafeBag.wireEncode());
    encryptedContent.setPayloadKey(memberKey.encrypt
      (secret, EncryptAlgorithmType.RsaOaep));

    Data kdkData = new Data(kdkName);
    kdkData.setContent(encryptedContent.wireEncodeV2());
    // FreshnessPeriod can serve as a soft access control for revoking access.
    kdkData.getMetaInfo().setFreshnessPeriod(DEFAULT_KDK_FRESHNESS_PERIOD_MS);
    keyChain_.sign(kdkData, new SigningInfo(identity_));

    storage_.insert(kdkData);

    return kdkData;
  }

  /**
   * Get the number of packets stored in in-memory storage.
   * @return The number of packets.
   */
  public final int
  size() { return storage_.size(); }

  /**
   * Get the the storage cache, which should only be used for testing.
   * @return The storage cache.
   */
  public final HashMap
  getCache_() { return storage_.getCache_(); }

  private final PibIdentity identity_;
  private PibKey nacKey_;
  private final KeyChain keyChain_;
  private final Face face_;

  // storage_ is for the KEK and KDKs.
  private final InMemoryStorageRetaining storage_ =
    new InMemoryStorageRetaining();
  private final long kekRegisteredPrefixId_;
  private final long kdkRegisteredPrefixId_;
  private static final Logger logger_ = Logger.getLogger(AccessManagerV2.class.getName());

  private static final double DEFAULT_KEK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
  private static final double DEFAULT_KDK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
}
