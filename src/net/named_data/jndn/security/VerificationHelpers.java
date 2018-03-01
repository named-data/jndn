/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/verification-helpers.cpp
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
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.SignedBlob;

/**
 * The VerificationHelpers class has static methods to verify signatures and
 * digests.
 */
public class VerificationHelpers {
  /**
   * Verify the buffer against the signature using the public key.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifySignature
    (ByteBuffer buffer, byte[] signature, PublicKey publicKey,
     DigestAlgorithm digestAlgorithm)
  {
    if (digestAlgorithm == DigestAlgorithm.SHA256) {
      if (publicKey.getKeyType() == KeyType.RSA) {
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          java.security.PublicKey securityPublicKey = keyFactory.generatePublic
            (new X509EncodedKeySpec(publicKey.getKeyDer().getImmutableArray()));

          java.security.Signature rsaSignature =
            java.security.Signature.getInstance("SHA256withRSA");
          rsaSignature.initVerify(securityPublicKey);
          rsaSignature.update(buffer);
          return rsaSignature.verify(signature);
        }
        catch (Exception ex) {
          return false;
        }
      }
      else if (publicKey.getKeyType() == KeyType.EC) {
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("EC");
          java.security.PublicKey securityPublicKey = keyFactory.generatePublic
            (new X509EncodedKeySpec(publicKey.getKeyDer().getImmutableArray()));

          java.security.Signature ecdsaSignature =
            java.security.Signature.getInstance("SHA256withECDSA");
          ecdsaSignature.initVerify(securityPublicKey);
          ecdsaSignature.update(buffer);
          return ecdsaSignature.verify(signature);
        }
        catch (Exception ex) {
          return false;
        }
      }
      else
        throw new IllegalArgumentException("verifySignature: Invalid key type");
    }
    else
      throw new IllegalArgumentException
        ("verifySignature: Invalid digest algorithm");
  }

  /**
   * Verify the buffer against the signature using the public key and
   * digest algorithm SHA256.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifySignature(ByteBuffer buffer, byte[] signature, PublicKey publicKey)
  {
    return verifySignature(buffer, signature, publicKey, DigestAlgorithm.SHA256);
  }

  /**
   * Verify the buffer against the signature using the public key.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifySignature
    (ByteBuffer buffer, Blob signature, PublicKey publicKey,
     DigestAlgorithm digestAlgorithm)
  {
    return verifySignature
      (buffer, signature.getImmutableArray(), publicKey, digestAlgorithm);
  }
  /**
   * Verify the buffer against the signature using the public key and
   * digest algorithm SHA256.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type.
   */

  public static boolean
  verifySignature(ByteBuffer buffer, Blob signature, PublicKey publicKey)
  {
    return verifySignature
      (buffer, signature.getImmutableArray(), publicKey,
       DigestAlgorithm.SHA256);
  }

  /**
   * Verify the buffer against the signature using the public key.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifySignature
    (Blob buffer, Blob signature, PublicKey publicKey,
     DigestAlgorithm digestAlgorithm)
  {
    return verifySignature
      (buffer.buf(), signature.getImmutableArray(), publicKey, digestAlgorithm);
  }

  /**
   * Verify the buffer against the signature using the public key and
   * digest algorithm SHA256.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKey The object containing the public key.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifySignature(Blob buffer, Blob signature, PublicKey publicKey)
  {
    return verifySignature
      (buffer.buf(), signature.getImmutableArray(), publicKey,
       DigestAlgorithm.SHA256);
  }

  /**
   * Verify the buffer against the signature using the encoded public key.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType or digestAlgorithm.
   */
  public static boolean
  verifySignature
    (ByteBuffer buffer, byte[] signature, Blob publicKeyDer,
     DigestAlgorithm digestAlgorithm)
  {
    try {
      return verifySignature
        (buffer, signature, new PublicKey(publicKeyDer), digestAlgorithm);
    } catch (UnrecognizedKeyFormatException ex) {
      return false;
    }
  }

  /**
   * Verify the buffer against the signature using the encoded public key and
   * digest algorithm SHA256.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType.
   */
  public static boolean
  verifySignature(ByteBuffer buffer, byte[] signature, Blob publicKeyDer)
  {
    return verifySignature
      (buffer, signature, publicKeyDer, DigestAlgorithm.SHA256);
  }

  /**
   * Verify the buffer against the signature using the encoded public key.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType or digestAlgorithm.
   */
  public static boolean
  verifySignature
    (ByteBuffer buffer, Blob signature, Blob publicKeyDer,
     DigestAlgorithm digestAlgorithm)
  {
    return verifySignature
      (buffer, signature.getImmutableArray(), publicKeyDer,
       digestAlgorithm);
  }

  /**
   * Verify the buffer against the signature using the encoded public key and
   * digest algorithm SHA256.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType.
   */
  public static boolean
  verifySignature(ByteBuffer buffer, Blob signature, Blob publicKeyDer)
  {
    return verifySignature
      (buffer, signature.getImmutableArray(), publicKeyDer,
       DigestAlgorithm.SHA256);
  }

  /**
   * Verify the buffer against the signature using the encoded public key.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType or digestAlgorithm.
   */
  public static boolean
  verifySignature
    (Blob buffer, Blob signature, Blob publicKeyDer,
     DigestAlgorithm digestAlgorithm)
  {
    return verifySignature
      (buffer.buf(), signature.getImmutableArray(), publicKeyDer,
       digestAlgorithm);
  }

  /**
   * Verify the buffer against the signature using the encoded public key and
   * digest algorithm SHA256.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifySignature with the
   * PublicKey object.
   * @param buffer The input buffer to verify.
   * @param signature The signature bytes.
   * @param publicKeyDer The DER-encoded public key.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid keyType.
   */
  public static boolean
  verifySignature(Blob buffer, Blob signature, Blob publicKeyDer)
  {
    return verifySignature
      (buffer.buf(), signature.getImmutableArray(), publicKeyDer,
       DigestAlgorithm.SHA256);
  }

  /**
   * Verify the Data packet using the public key. This does not check the
   * type of public key or digest algorithm against the type of SignatureInfo in
   * the Data packet such as Sha256WithRsaSignature.
   * @param data The Data packet to verify.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, PublicKey publicKey, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    SignedBlob encoding = data.wireEncode(wireFormat);
    return verifySignature
      (encoding.signedBuf(), data.getSignature().getSignature(), publicKey,
       digestAlgorithm);
  }

  /**
   * Verify the Data packet using the public key. This does not check the
   * type of public key or digest algorithm against the type of SignatureInfo in
   * the Data packet such as Sha256WithRsaSignature.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, PublicKey publicKey, DigestAlgorithm digestAlgorithm)
  {
    return verifyDataSignature
      (data, publicKey, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Data packet using the public key and digest algorithm SHA256.
   * This does not check the type of public key or digest algorithm against the
   * type of SignatureInfo in the Data packet such as Sha256WithRsaSignature.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param publicKey The object containing the public key.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifyDataSignature(Data data, PublicKey publicKey)
  {
    return verifyDataSignature
      (data, publicKey, DigestAlgorithm.SHA256, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Data packet using the public key. This does not check the
   * type of public key or digest algorithm against the type of SignatureInfo in
   * the Data packet such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyDataSignature with the
   * PublicKey object.
   * @param data The Data packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, Blob publicKeyDer, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    try {
      return verifyDataSignature
        (data, new PublicKey(publicKeyDer), digestAlgorithm);
    } catch (UnrecognizedKeyFormatException ex) {
      return false;
    }
  }

  /**
   * Verify the Data packet using the public key. This does not check the
   * type of public key or digest algorithm against the type of SignatureInfo in
   * the Data packet such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyDataSignature with the
   * PublicKey object.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, Blob publicKeyDer, DigestAlgorithm digestAlgorithm)
  {
    return verifyDataSignature
      (data, publicKeyDer, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Data packet using the public key and digest algorithm SHA256.
   * This does not check the type of public key or digest algorithm against the
   * type of SignatureInfo in the Data packet such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyDataSignature with the
   * PublicKey object.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature(Data data, Blob publicKeyDer)
  {
    return verifyDataSignature
      (data, publicKeyDer, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Data packet using the public key in the certificate. This does
   * not check the type of public key or digest algorithm against the type of
   * SignatureInfo in the Data packet such as Sha256WithRsaSignature.
   * @param data The Data packet to verify.
   * @param certificate The certificate containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, CertificateV2 certificate, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    try {
      return verifyDataSignature
        (data, certificate.getPublicKey(), digestAlgorithm, wireFormat);
    } catch (CertificateV2.Error ex) {
      return false;
    }
  }

  /**
   * Verify the Data packet using the public key in the certificate. This does
   * not check the type of public key or digest algorithm against the type of
   * SignatureInfo in the Data packet such as Sha256WithRsaSignature.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param certificate The certificate containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyDataSignature
    (Data data, CertificateV2 certificate, DigestAlgorithm digestAlgorithm)
  {
    return verifyDataSignature
      (data, certificate, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Data packet using the public key in the certificate and digest
   * algorithm SHA256. This does not check the type of public key or digest
   * algorithm against the type of SignatureInfo in the Data packet such as
   * Sha256WithRsaSignature.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param certificate The certificate containing the public key.
   * @return True if verification succeeds, false if verification fails or for
   * an error decoding the public key.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifyDataSignature(Data data, CertificateV2 certificate)
  {
    return verifyDataSignature
      (data, certificate, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key, where the last two name
   * components are the SignatureInfo and signature bytes. This does not check
   * the type of public key or digest algorithm against the type of
   * SignatureInfo such as Sha256WithRsaSignature.
   * @param interest The Interest packet to verify.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @param wireFormat A WireFormat object used to decode the Interest packet.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, PublicKey publicKey, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    Signature signature = extractSignature(interest, wireFormat);
    if (signature == null)
      return false;

    SignedBlob encoding = interest.wireEncode(wireFormat);

    return verifySignature
      (encoding.signedBuf(), signature.getSignature(),
       publicKey, digestAlgorithm);
  }

  /**
   * Verify the Interest packet using the public key, where the last two name
   * components are the SignatureInfo and signature bytes. This does not check
   * the type of public key or digest algorithm against the type of
   * SignatureInfo such as Sha256WithRsaSignature.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param publicKey The object containing the public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, PublicKey publicKey, DigestAlgorithm digestAlgorithm)
  {
    return verifyInterestSignature
      (interest, publicKey, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key and digest algorithm SHA256,
   * where the last two name components are the SignatureInfo and signature
   * bytes. This does not check the type of public key or digest algorithm
   * against the type of SignatureInfo such as Sha256WithRsaSignature.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param publicKey The object containing the public key.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifyInterestSignature(Interest interest, PublicKey publicKey)
  {
    return verifyInterestSignature
      (interest, publicKey, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key, where the last two name
   * components are the SignatureInfo and signature bytes. This does not check
   * the type of public key or digest algorithm against the type of
   * SignatureInfo such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyInterestSignature with
   * the PublicKey object.
   * @param interest The Interest packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @param wireFormat A WireFormat object used to decode the Interest packet.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, Blob publicKeyDer, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    try {
      return verifyInterestSignature
        (interest, new PublicKey(publicKeyDer), digestAlgorithm);
    } catch (UnrecognizedKeyFormatException ex) {
      return false;
    }
  }

  /**
   * Verify the Interest packet using the public key, where the last two name
   * components are the SignatureInfo and signature bytes. This does not check
   * the type of public key or digest algorithm against the type of
   * SignatureInfo such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyInterestSignature with
   * the PublicKey object.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @param digestAlgorithm The digest algorithm.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, Blob publicKeyDer, DigestAlgorithm digestAlgorithm)
  {
    return verifyInterestSignature
      (interest, publicKeyDer, digestAlgorithm,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key and digest algorithm SHA256,
   * where the last two name components are the SignatureInfo and signature
   * bytes. This does not check the type of public key or digest algorithm
   * against the type of SignatureInfo such as Sha256WithRsaSignature.
   * If the public key can't be decoded, this returns false instead of throwing
   * a decoding exception. If you want to get a decoding exception then use
   * the PublicKey constructor to decode and call verifyInterestSignature with
   * the PublicKey object.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param publicKeyDer The DER-encoded public key.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifyInterestSignature(Interest interest, Blob publicKeyDer)
  {
    return verifyInterestSignature
      (interest, publicKeyDer, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key in the certificate, where
   * the last two name components are the SignatureInfo and signature bytes.
   * This does not check the type of public key or digest algorithm against the
   * type of SignatureInfo such as Sha256WithRsaSignature.
   * @param interest The Interest packet to verify.
   * @param certificate The certificate containing the public key.
   * @param digestAlgorithm (optional) The digest algorithm. If omitted, use SHA256.
   * @param wireFormat (optional) A WireFormat object used to decode the
   * Interest packet. If omitted, use WireFormat getDefaultWireFormat().
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, CertificateV2 certificate,
     DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    try {
      return verifyInterestSignature
        (interest, certificate.getPublicKey(), digestAlgorithm, wireFormat);
    } catch (CertificateV2.Error ex) {
      return false;
    }
  }

  /**
   * Verify the Interest packet using the public key in the certificate, where
   * the last two name components are the SignatureInfo and signature bytes.
   * This does not check the type of public key or digest algorithm against the
   * type of SignatureInfo such as Sha256WithRsaSignature.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param certificate The certificate containing the public key.
   * @param digestAlgorithm (optional) The digest algorithm. If omitted, use SHA256.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type or
   * digestAlgorithm.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, CertificateV2 certificate,
     DigestAlgorithm digestAlgorithm)
  {
    return verifyInterestSignature
      (interest, certificate, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the public key and digest algorithm SHA256
   * in the certificate, where the last two name components are the
   * SignatureInfo and signature bytes.
   * This does not check the type of public key or digest algorithm against the
   * type of SignatureInfo such as Sha256WithRsaSignature.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param certificate The certificate containing the public key.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest or public key.
   * @throws IllegalArgumentException for an invalid public key type.
   */
  public static boolean
  verifyInterestSignature
    (Interest interest, CertificateV2 certificate)
  {
    return verifyInterestSignature
      (interest, certificate, DigestAlgorithm.SHA256,
       WireFormat.getDefaultWireFormat());
  }

  /////////////////////////////////////////////////////////////

  /**
   * Verify the buffer against the digest using the digest algorithm.
   * @param buffer The input buffer to verify.
   * @param digest The digest bytes.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyDigest
    (ByteBuffer buffer, byte[] digest, DigestAlgorithm digestAlgorithm)
  {
    if (digestAlgorithm == DigestAlgorithm.SHA256) {
      byte[] bufferDigest = Common.digestSha256(buffer);
      return Arrays.equals(bufferDigest, digest);
    }
    else
      throw new IllegalArgumentException
        ("verifyDigest: Invalid digest algorithm");
  }

  /**
   * Verify the buffer against the digest using the digest algorithm.
   * @param buffer The input buffer to verify.
   * @param digest The digest bytes.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyDigest
    (ByteBuffer buffer, Blob digest, DigestAlgorithm digestAlgorithm)
  {
    return verifyDigest(buffer, digest.getImmutableArray(), digestAlgorithm);
  }

  /**
   * Verify the buffer against the digest using the digest algorithm.
   * @param buffer The input buffer to verify.
   * @param digest The digest bytes.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyDigest
    (Blob buffer, Blob digest, DigestAlgorithm digestAlgorithm)
  {
    return verifyDigest
      (buffer.buf(), digest.getImmutableArray(), digestAlgorithm);
  }

  /**
   * Verify the Data packet using the digest algorithm. This does not check the
   * digest algorithm against the type of SignatureInfo in the Data packet such
   * as DigestSha256Signature.
   * @param data The Data packet to verify.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyDataDigest
    (Data data, DigestAlgorithm digestAlgorithm, WireFormat wireFormat)
  {
    SignedBlob encoding = data.wireEncode(wireFormat);
    return verifyDigest
      (encoding.signedBuf(), data.getSignature().getSignature(),
       digestAlgorithm);
  }

  /**
   * Verify the Data packet using the digest algorithm. This does not check the
   * digest algorithm against the type of SignatureInfo in the Data packet such
   * as DigestSha256Signature.
   * Encode the Data packet with the default wire format.
   * @param data The Data packet to verify.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @return True if verification succeeds, false if verification fails.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyDataDigest(Data data, DigestAlgorithm digestAlgorithm)
  {
    return verifyDataDigest
      (data, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Verify the Interest packet using the digest algorithm, where the last two
   * name components are the SignatureInfo and signature bytes. This does not
   * check the digest algorithm against the type of SignatureInfo such as
   * DigestSha256Signature.
   * @param interest The Interest packet to verify.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @param wireFormat A WireFormat object used to decode the Interest packet.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyInterestDigest
    (Interest interest, DigestAlgorithm digestAlgorithm,
     WireFormat wireFormat)
  {
    Signature signature = extractSignature(interest, wireFormat);
    if (signature == null)
      return false;

    SignedBlob encoding = interest.wireEncode(wireFormat);
    return verifyDigest
      (encoding.signedBuf(), signature.getSignature(), digestAlgorithm);
  }

  /**
   * Verify the Interest packet using the digest algorithm, where the last two
   * name components are the SignatureInfo and signature bytes. This does not
   * check the digest algorithm against the type of SignatureInfo such as
   * DigestSha256Signature.
   * Decode the Interest packet with the default wire format.
   * @param interest The Interest packet to verify.
   * @param digestAlgorithm The digest algorithm, such as DigestAlgorithm.SHA256.
   * @return True if verification succeeds, false if verification fails or
   * cannot decode the Interest.
   * @throws IllegalArgumentException for an invalid digestAlgorithm.
   */
  public static boolean
  verifyInterestDigest(Interest interest, DigestAlgorithm digestAlgorithm)
  {
    return verifyInterestDigest
      (interest, digestAlgorithm, WireFormat.getDefaultWireFormat());
  }

  /**
   * Extract the signature information from the interest name.
   * @param interest The interest whose signature is needed.
   * @param wireFormat The wire format used to decode signature information
   * from the interest name.
   * @return The Signature object, or null if can't decode.
   */
  private static Signature
  extractSignature(Interest interest, WireFormat wireFormat)
  {
    if (interest.getName().size() < 2)
      return null;

    try {
      return wireFormat.decodeSignatureInfoAndValue
              (interest.getName().get(-2).getValue().buf(),
               interest.getName().get(-1).getValue().buf(), false);
    } catch (EncodingException ex) {
      return null;
    }
  }
}
