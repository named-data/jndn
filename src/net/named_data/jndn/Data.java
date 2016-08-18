/**
 * Copyright (C) 2013-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn;

import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.SignatureHolder;
import net.named_data.jndn.lp.IncomingFaceId;
import net.named_data.jndn.lp.LpPacket;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCounter;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.SignedBlob;

public class Data implements ChangeCountable, SignatureHolder {
  /**
   * Create a new Data object with default values and where the signature is a
   * blank Sha256WithRsaSignature.
   */
  public Data()
  {
  }

  /**
   * Create a new Data object with the given name and default values and where
   * the signature is a blank Sha256WithRsaSignature.
   * @param name The name which is copied.
   */
  public Data(Name name)
  {
    name_.set(new Name(name));
  }

  /**
   * Create a deep copy of the given data object, including a clone of the
   * signature object.
   * @param data The data object to copy.
   */
  public Data(Data data)
  {
    try {
      signature_.set(data.signature_ == null ?
        new Sha256WithRsaSignature() : (Signature)data.getSignature().clone());
    }
    catch (CloneNotSupportedException e) {
      // We don't expect this to happen, so just treat it as if we got a null pointer.
      throw new NullPointerException
        ("Data.setSignature: unexpected exception in clone(): " + e.getMessage());
    }

    name_.set(new Name(data.getName()));
    metaInfo_.set(new MetaInfo(data.getMetaInfo()));
    content_ = data.content_;
    setDefaultWireEncoding(data.defaultWireEncoding_, null);
  }

  /**
   * Encode this Data for a particular wire format. If wireFormat is the default
   * wire format, also set the defaultWireEncoding field to the encoded result.
   * @param wireFormat A WireFormat object used to encode the input.
   * @return The encoded buffer.
   */
  public final SignedBlob
  wireEncode(WireFormat wireFormat)
  {
    if (!getDefaultWireEncoding().isNull() &&
        getDefaultWireEncodingFormat() == wireFormat)
      // We already have an encoding in the desired format.
      return getDefaultWireEncoding();

    int[] signedPortionBeginOffset = new int[1];
    int[] signedPortionEndOffset = new int[1];
    Blob encoding = wireFormat.encodeData
      (this, signedPortionBeginOffset, signedPortionEndOffset);
    SignedBlob wireEncoding = new SignedBlob
      (encoding, signedPortionBeginOffset[0], signedPortionEndOffset[0]);

    if (wireFormat == WireFormat.getDefaultWireFormat())
      // This is the default wire encoding.
      setDefaultWireEncoding(wireEncoding, WireFormat.getDefaultWireFormat());

    return wireEncoding;
  }

  /**
   * Encode this Data for the default wire format WireFormat.getDefaultWireFormat().
   * Also set the defaultWireEncoding field to the encoded result.
   * @return The encoded buffer.
   */
  public final SignedBlob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this Data. If
   * wireFormat is the default wire format, also set the defaultWireEncoding
   * field another pointer to the input Blob.
   * @param input The input Blob to decode.  This reads from buf().position() to
   * buf().limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    int[] signedPortionBeginOffset = new int[1];
    int[] signedPortionEndOffset = new int[1];
    wireFormat.decodeData
      (this, input.buf(), signedPortionBeginOffset, signedPortionEndOffset,
       false);

    if (wireFormat == WireFormat.getDefaultWireFormat())
      // This is the default wire encoding.
      setDefaultWireEncoding
        (new SignedBlob(input, signedPortionBeginOffset[0],
         signedPortionEndOffset[0]), WireFormat.getDefaultWireFormat());
    else
      setDefaultWireEncoding(new SignedBlob(), null);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Data. Also set the
   * defaultWireEncoding field another pointer to the input Blob.
   * @param input The input Blob to decode.  This reads from buf().position() to
   * buf().limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this Data. If
   * wireFormat is the default wire format, also set the defaultWireEncoding
   * field to a copy of the input. (To not copy the input, see
   * wireDecode(Blob).)
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireDecode(new Blob(input, true), wireFormat);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Data. Also set the
   * defaultWireEncoding field to the input.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  public final Signature
  getSignature() { return (Signature)signature_.get(); }

  public final Name
  getName() { return (Name)name_.get(); }

  public final MetaInfo
  getMetaInfo() { return (MetaInfo)metaInfo_.get(); }

  public final Blob
  getContent() { return content_; }

  /**
   * Get the incoming face ID according to the incoming packet header.
   * @return The incoming face ID. If not specified, return -1.
   */
  public final long
  getIncomingFaceId()
  {
    IncomingFaceId field = 
      lpPacket_ == null ? null : IncomingFaceId.getFirstHeader(lpPacket_);
    return field == null ? -1 : field.getFaceId();
  }

  /**
   * Get the Data packet's full name, which includes the final
   * ImplicitSha256Digest component based on the wire encoding for a particular
   * wire format.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @return The full name. You must not change the Name object - if you need
   * to change it then make a copy.
   */
  public final Name
  getFullName(WireFormat wireFormat) throws EncodingException
  {
    // The default full name depends on the default wire encoding.
    if (!getDefaultWireEncoding().isNull() && defaultFullName_.size() > 0 &&
        getDefaultWireEncodingFormat() == wireFormat)
      // We already have a full name. A non-null default wire encoding means
      // that the Data packet fields have not changed.
      return defaultFullName_;

    Name fullName = new Name(getName());
    // wireEncode will use the cached encoding if possible.
    fullName.appendImplicitSha256Digest
      (Common.digestSha256(wireEncode(wireFormat).buf()));

    if (wireFormat == WireFormat.getDefaultWireFormat())
      // wireEncode has already set defaultWireEncodingFormat_.
      defaultFullName_ = fullName;

    return fullName;
  }

  /**
   * Get the Data packet's full name, which includes the final
   * ImplicitSha256Digest component based on the wire encoding for the default
   * wire format.
   * @return The full name. You must not change the Name objects - if you need
   * to change it then make a copy.
   */
  public final Name
  getFullName() throws EncodingException
  {
    return getFullName(WireFormat.getDefaultWireFormat());
  }

  /**
   * Return a pointer to the defaultWireEncoding, which was encoded with
   * getDefaultWireEncodingFormat().
   * @return The default wire encoding. Its pointer may be null.
   */
  public final SignedBlob
  getDefaultWireEncoding()
  {
    if (getDefaultWireEncodingChangeCount_ != getChangeCount()) {
      // The values have changed, so the default wire encoding is invalidated.
      defaultWireEncoding_ = new SignedBlob();
      defaultWireEncodingFormat_ = null;
      getDefaultWireEncodingChangeCount_ = getChangeCount();
    }

    return defaultWireEncoding_;
  }

  /**
   * Get the WireFormat which is used by getDefaultWireEncoding().
   * @return The WireFormat, which is only meaningful if the
   * getDefaultWireEncoding() does not have a null pointer.
   */
  WireFormat
  getDefaultWireEncodingFormat() { return defaultWireEncodingFormat_; }

  /**
   * Set the signature to a copy of the given signature.
   * @param signature The signature object which is cloned.
   * @return This Data so that you can chain calls to update values.
   */
  public final Data
  setSignature(Signature signature)
  {
    try {
      signature_.set(signature == null ?
        new Sha256WithRsaSignature() : (Signature)signature.clone());
    }
    catch (CloneNotSupportedException e) {
      // We don't expect this to happen, so just treat it as if we got a null
      //   pointer.
      throw new NullPointerException
        ("Data.setSignature: unexpected exception in clone(): " + e.getMessage());
    }

    ++changeCount_;
    return this;
  }

  /**
   * Set name to a copy of the given Name.  This is not final so that a subclass
   * can override to validate the name.
   * @param name The Name which is copied.
   * @return This Data so that you can chain calls to update values.
   */
  public Data
  setName(Name name)
  {
    name_.set(name == null ? new Name() : new Name(name));
    ++changeCount_;
    return this;
  }

  /**
   * Set metaInfo to a copy of the given MetaInfo.
   * @param metaInfo The MetaInfo which is copied.
   * @return This Data so that you can chain calls to update values.
   */
  public final Data
  setMetaInfo(MetaInfo metaInfo)
  {
    metaInfo_.set(metaInfo == null ? new MetaInfo() : new MetaInfo(metaInfo));
    ++changeCount_;
    return this;
  }

  public final Data
  setContent(Blob content)
  {
    content_ = (content == null ? new Blob() : content);
    ++changeCount_;
    return this;
  }

  /**
   * An internal library method to set the LpPacket for an incoming packet. The
   * application should not call this.
   * @param lpPacket The LpPacket. This does not make a copy.
   * @return This Data so that you can chain calls to update values.
   * @note This is an experimental feature. This API may change in the future.
   */
  final Data
  setLpPacket(LpPacket lpPacket)
  {
    lpPacket_ = lpPacket;
    // Don't update changeCount_ since this doesn't affect the wire encoding.
    return this;
  }

  /**
   * Get the change count, which is incremented each time this object
   * (or a child object) is changed.
   * @return The change count.
   */
  public final long
  getChangeCount()
  {
    // Make sure each of the checkChanged is called.
    boolean changed = signature_.checkChanged();
    changed = name_.checkChanged() || changed;
    changed = metaInfo_.checkChanged() || changed;
    if (changed)
      // A child object has changed, so update the change count.
      ++changeCount_;

    return changeCount_;
  }

  private void
  setDefaultWireEncoding
    (SignedBlob defaultWireEncoding, WireFormat defaultWireEncodingFormat)
  {
    defaultWireEncoding_ = defaultWireEncoding;
    defaultWireEncodingFormat_ = defaultWireEncodingFormat;
    // Set getDefaultWireEncodingChangeCount_ so that the next call to
    //   getDefaultWireEncoding() won't clear defaultWireEncoding_.
    getDefaultWireEncodingChangeCount_ = getChangeCount();
  }

  private final ChangeCounter signature_ =
    new ChangeCounter(new Sha256WithRsaSignature());
  private final ChangeCounter name_ = new ChangeCounter(new Name());
  private final ChangeCounter metaInfo_ =
    new ChangeCounter(new MetaInfo());
  private Blob content_ = new Blob();
  private LpPacket lpPacket_ = null;
  private SignedBlob defaultWireEncoding_ = new SignedBlob();
  private Name defaultFullName_ = new Name();
  private WireFormat defaultWireEncodingFormat_;
  private long getDefaultWireEncodingChangeCount_ = 0;
  private long changeCount_ = 0;
}
