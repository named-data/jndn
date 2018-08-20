/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/encrypted-content https://github.com/named-data/ndn-group-encrypt
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

import java.nio.ByteBuffer;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.util.Blob;

/**
 * An EncryptedContent holds an encryption type, a payload and other fields
 * representing encrypted content.
 * @note This class is an experimental feature. The API may change.
 */
public class EncryptedContent {
  /**
   * Create an EncryptedContent where all the values are unspecified.
   */
  public EncryptedContent()
  {}

  /**
   * Create an EncryptedContent as a deep copy of the given object.
   * @param encryptedContent The other encryptedContent to copy.
   */
  public EncryptedContent(EncryptedContent encryptedContent)
  {
    algorithmType_ = encryptedContent.algorithmType_;
    keyLocator_ = new KeyLocator(encryptedContent.keyLocator_);
    initialVector_ = encryptedContent.initialVector_;
    payload_ = encryptedContent.payload_;
  }

  /**
   * Get the algorithm type.
   * @return The algorithm type. If not specified, return
   * EncryptAlgorithmType.NONE.
   */
  public final EncryptAlgorithmType
  getAlgorithmType() { return algorithmType_; }

  /**
   * Get the key locator.
   * @return The key locator. If not specified, getType() is KeyLocatorType.NONE.
   */
  public final KeyLocator
  getKeyLocator() { return keyLocator_; }

  /**
   * Check that the key locator type is KEYNAME and return the key Name.
   * @return The key Name.
   * @throws Error if the key locator type is not KEYNAME.
   */
  public final Name
  getKeyLocatorName()
  {
    if (keyLocator_.getType() != KeyLocatorType.KEYNAME)
      throw new Error("getKeyLocatorName: The KeyLocator type must be KEYNAME");

    return keyLocator_.getKeyName();
  }

  /**
   * Check if the initial vector is specified.
   * @return True if the initial vector is specified.
   */
  public final boolean
  hasInitialVector() { return !initialVector_.isNull(); }

  /**
   * Get the initial vector.
   * @return The initial vector. If not specified, isNull() is true.
   */
  public final Blob
  getInitialVector() { return initialVector_; }

  /**
   * Get the payload.
   * @return The payload. If not specified, isNull() is true.
   */
  public final Blob
  getPayload() { return payload_; }

  /**
   * Get the encrypted payload key.
   * @return The encrypted payload key. If not specified, isNull() is true.
   */
  public final Blob
  getPayloadKey() { return payloadKey_; }

  /**
   * Set the algorithm type.
   * @param algorithmType The algorithm type. If not specified, set to
   * EncryptAlgorithmType.NONE.
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setAlgorithmType(EncryptAlgorithmType algorithmType)
  {
    algorithmType_ = algorithmType;
    return this;
  }

  /**
   * Set the key locator.
   * @param keyLocator The key locator. This makes a copy of the object. If not
   *   specified, set to the default KeyLocator().
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setKeyLocator(KeyLocator keyLocator)
  {
    keyLocator_ = keyLocator == null ?
      new KeyLocator() : new KeyLocator(keyLocator);
    return this;
  }

  /**
   * Set the key locator type to KeyLocatorType.KEYNAME and set the key Name.
   * @param keyName The key locator Name, which is copied.
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setKeyLocatorName(Name keyName)
  {
    keyLocator_.setType(KeyLocatorType.KEYNAME);
    keyLocator_.setKeyName(keyName);
    return this;
  }

  /**
   * Set the initial vector.
   * @param initialVector The initial vector. If not specified, set to the
   * default Blob() where isNull() is true.
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setInitialVector(Blob initialVector)
  {
    initialVector_ = (initialVector == null ? new Blob() : initialVector);
    return this;
  }

  /**
   * Set the encrypted payload.
   * @param payload The payload. If not specified, set to the default Blob()
   * where isNull() is true.
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setPayload(Blob payload)
  {
    payload_ = (payload == null ? new Blob() : payload);
    return this;
  }

  /**
   * Set the encrypted payload key.
   * @param payloadKey The encrypted payload key. If not specified, set to the
   * default Blob() where isNull() is true.
   * @return This EncryptedContent so that you can chain calls to update values.
   */
  public final EncryptedContent
  setPayloadKey(Blob payloadKey)
  {
    payloadKey_ = (payloadKey == null ? new Blob() : payloadKey);
    return this;
  }

  /**
   * Set all the fields to indicate unspecified values.
   */
  public final void
  clear()
  {
    algorithmType_ = EncryptAlgorithmType.NONE;
    keyLocator_ = new KeyLocator();
    initialVector_ = new Blob();
    payload_ = new Blob();
    payloadKey_ = new Blob();
  }

  /**
   * Encode this to an EncryptedContent v1 wire encoding.
   * @param wireFormat A WireFormat object used to encode this EncryptedContent.
   * @return The encoded byte array as a Blob.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeEncryptedContent(this);
  }

  /**
   * Encode this to an EncryptedContent v1 for the default wire format.
   * @return The encoded byte array as a Blob.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode this to an EncryptedContent v2 wire encoding.
   * @param wireFormat A WireFormat object used to encode this EncryptedContent.
   * @return The encoded byte array as a Blob.
   */
  public final Blob
  wireEncodeV2(WireFormat wireFormat)
  {
    return wireFormat.encodeEncryptedContentV2(this);
  }

  /**
   * Encode this to an EncryptedContent v2 for the default wire format.
   * @return The encoded byte array as a Blob.
   */
  public final Blob
  wireEncodeV2()
  {
    return wireEncodeV2(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input as an EncryptedContent v1 using a particular wire format
   * and update this EncryptedContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeEncryptedContent(this, input, true);
  }

  /**
   * Decode the input as an EncryptedContent v1 using the default wire format
   * and update this EncryptedContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input as an EncryptedContent v1 using a particular wire format
   * and update this EncryptedContent.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeEncryptedContent(this, input.buf(), false);
  }

  /**
   * Decode the input as an EncryptedContent v1 using the default wire format
   * and update this EncryptedContent.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input as an EncryptedContent v2 using a particular wire format
   * and update this EncryptedContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecodeV2(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeEncryptedContentV2(this, input, true);
  }

  /**
   * Decode the input as an EncryptedContent v2 using the default wire format
   * and update this EncryptedContent.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecodeV2(ByteBuffer input) throws EncodingException
  {
    wireDecodeV2(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input as an EncryptedContent v2 using a particular wire format
   * and update this EncryptedContent.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecodeV2(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeEncryptedContentV2(this, input.buf(), false);
  }

  /**
   * Decode the input as an EncryptedContent v2 using the default wire format
   * and update this EncryptedContent.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecodeV2(Blob input) throws EncodingException
  {
    wireDecodeV2(input, WireFormat.getDefaultWireFormat());
  }

  private EncryptAlgorithmType algorithmType_ = EncryptAlgorithmType.NONE;
  private KeyLocator keyLocator_ = new KeyLocator();
  private Blob initialVector_ = new Blob();
  private Blob payload_ = new Blob();
  private Blob payloadKey_ = new Blob();
}
