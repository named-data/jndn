/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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
import java.util.Random;

import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.lp.IncomingFaceId;
import net.named_data.jndn.lp.LpPacket;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.util.ChangeCounter;
import net.named_data.jndn.util.SignedBlob;

/**
 * An Interest holds a Name and other fields for an interest.
 */
public class Interest implements ChangeCountable {
  /**
   * Create a new Interest with the given name and interest lifetime and "none"
   * for other values.
   * @param name The name for the interest.
   * @param interestLifetimeMilliseconds The interest lifetime in milliseconds,
   * or -1 for none.
   */
  public
  Interest(Name name, double interestLifetimeMilliseconds)
  {
    if (name != null)
      name_.set(new Name(name));
    interestLifetimeMilliseconds_ = interestLifetimeMilliseconds;
  }

  /**
   * Create a new Interest with the given name and "none" for other values.
   * @param name The name for the interest.
   */
  public
  Interest(Name name)
  {
    if (name != null)
      name_.set(new Name(name));
  }

  /**
   * Create a new Interest with a Name from the given URI string, and "none" for
   * other values.
   * @param uri The URI string.
   */
  public
  Interest(String uri)
  {
    name_.set(new Name(uri));
  }

  /**
   * Create a new interest as a deep copy of the given interest.
   * @param interest The interest to copy.
   */
  public
  Interest(Interest interest)
  {
    name_.set(new Name(interest.getName()));
    minSuffixComponents_ = interest.minSuffixComponents_;
    maxSuffixComponents_ = interest.maxSuffixComponents_;
    keyLocator_.set(new KeyLocator(interest.getKeyLocator()));
    exclude_.set(new Exclude(interest.getExclude()));
    childSelector_ = interest.childSelector_;
    mustBeFresh_ = interest.mustBeFresh_;

    interestLifetimeMilliseconds_ = interest.interestLifetimeMilliseconds_;
    nonce_ = interest.getNonce();

    forwardingHint_.set(new DelegationSet(interest.getForwardingHint()));
    linkWireEncoding_ = interest.linkWireEncoding_;
    linkWireEncodingFormat_ = interest.linkWireEncodingFormat_;
    if (interest.link_.get() != null)
      link_.set(new Link((Link)interest.link_.get()));
    selectedDelegationIndex_ = interest.selectedDelegationIndex_;

    setDefaultWireEncoding
      (interest.getDefaultWireEncoding(), interest.defaultWireEncodingFormat_);
  }

  /**
   * Create a new Interest with an empty name and "none" for all values.
   */
  public
  Interest()
  {
  }

  public static final int CHILD_SELECTOR_LEFT = 0;
  public static final int CHILD_SELECTOR_RIGHT = 1;

  /**
   * Encode this Interest for a particular wire format. If wireFormat is the
   * default wire format, also set the defaultWireEncoding field to the encoded
   * result.
   * @param wireFormat A WireFormat object used to encode this Interest.
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
    Blob encoding = wireFormat.encodeInterest
      (this, signedPortionBeginOffset, signedPortionEndOffset);
    SignedBlob wireEncoding = new SignedBlob
      (encoding, signedPortionBeginOffset[0], signedPortionEndOffset[0]);

    if (wireFormat == WireFormat.getDefaultWireFormat())
      // This is the default wire encoding.
      setDefaultWireEncoding(wireEncoding, WireFormat.getDefaultWireFormat());

    return wireEncoding;
  }

  /**
   * Encode this Interest for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final SignedBlob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this Interest.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireDecodeHelper(input, wireFormat, true);
  }

  private void
  wireDecodeHelper
    (ByteBuffer input, WireFormat wireFormat, boolean copy) throws EncodingException
  {
    int[] signedPortionBeginOffset = new int[1];
    int[] signedPortionEndOffset = new int[1];
    wireFormat.decodeInterest
      (this, input, signedPortionBeginOffset, signedPortionEndOffset, copy);

    if (wireFormat == WireFormat.getDefaultWireFormat())
      // This is the default wire encoding.
      setDefaultWireEncoding
        (new SignedBlob(input, copy, signedPortionBeginOffset[0],
         signedPortionEndOffset[0]), WireFormat.getDefaultWireFormat());
    else
      setDefaultWireEncoding(new SignedBlob(), null);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Interest.
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
   * Decode the input using a particular wire format and update this Interest. If
   * wireFormat is the default wire format, also set the defaultWireEncoding
   * field another pointer to the input Blob.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireDecodeHelper(input.buf(), wireFormat, false);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Interest.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode the name according to the "NDN URI Scheme".  If there are interest
   * selectors, append "?" and added the selectors as a query string.  For
   * example "/test/name?ndn.ChildSelector=1".
   * @return The URI string.
   * @note This is an experimental feature.  See the API docs for more detail at
   * http://named-data.net/doc/ndn-ccl-api/interest.html#interest-touri-method .
   */
  public final String
  toUri()
  {
    StringBuffer selectors = new StringBuffer();

    if (minSuffixComponents_ >= 0)
      selectors.append("&ndn.MinSuffixComponents=").append(minSuffixComponents_);
    if (maxSuffixComponents_ >= 0)
      selectors.append("&ndn.MaxSuffixComponents=").append(maxSuffixComponents_);
    if (childSelector_ >= 0)
      selectors.append("&ndn.ChildSelector=").append(childSelector_);
    selectors.append("&ndn.MustBeFresh=").append(mustBeFresh_ ? 1 : 0);
    if (interestLifetimeMilliseconds_ >= 0)
      selectors.append("&ndn.InterestLifetime=").append
        ((long)Math.round(interestLifetimeMilliseconds_));
    if (nonce_.size() > 0) {
      selectors.append("&ndn.Nonce=");
      Name.toEscapedString(nonce_.buf(), selectors);
    }
    if (getExclude().size() > 0)
      selectors.append("&ndn.Exclude=").append(getExclude().toUri());

    StringBuffer result = new StringBuffer();

    result.append(getName().toUri());
    String selectorsString = selectors.toString();
    if (selectorsString.length() > 0)
      // Replace the first & with ?.
      result.append("?").append(selectorsString.substring(1));

    return result.toString();
  }

  public final Name
  getName() { return (Name)name_.get(); }

  public final int
  getMinSuffixComponents() { return minSuffixComponents_; }

  public final int
  getMaxSuffixComponents() { return maxSuffixComponents_; }

  /**
   * Get the CanBePrefix flag. If not specified, the default is true.
   * @return The CanBePrefix flag.
   */
  public final boolean
  getCanBePrefix()
  {
    // Use the closest v0.2 semantics. CanBePrefix is the opposite of exact
    // match where MaxSuffixComponents is 1 (for the implicit digest).
    return maxSuffixComponents_ != 1;
  }

  public final KeyLocator
  getKeyLocator() { return (KeyLocator)keyLocator_.get(); }

  public final Exclude
  getExclude() { return (Exclude)exclude_.get(); }

  public final int
  getChildSelector() { return childSelector_; }

  /**
   * Get the must be fresh flag. If not specified, the default is true.
   * @return The must be fresh flag.
   */
  public final boolean
  getMustBeFresh() { return mustBeFresh_; }

  public final double
  getInterestLifetimeMilliseconds() { return interestLifetimeMilliseconds_; }

  /**
   * Return the nonce value from the incoming interest.  If you change any of
   * the fields in this Interest object, then the nonce value is cleared.
   * @return The nonce.
   */
  public final Blob
  getNonce()
  {
    if (getNonceChangeCount_ != getChangeCount()) {
      // The values have changed, so the existing nonce is invalidated.
      nonce_ = new Blob();
      getNonceChangeCount_ = getChangeCount();
    }

    return nonce_;
  }

  /**
   * Get the forwarding hint object which you can modify to add or remove
   * forwarding hints.
   * @return The forwarding hint as a DelegationSet.
   */
  public final DelegationSet
  getForwardingHint() { return (DelegationSet)forwardingHint_.get(); }

  /**
   * Check if this interest has a link object (or a link wire encoding which
   * can be decoded to make the link object).
   * @return True if this interest has a link object, false if not.
   * @deprecated Use getForwardingHint.
   */
  public final boolean
  hasLink()
  {
    return link_.get() != null || !linkWireEncoding_.isNull();
  }

  /**
   * Get the link object. If necessary, decode it from the link wire encoding.
   * @return  The link object, or null if not specified.
   * @throws EncodingException For error decoding the link wire encoding (if
   * necessary).
   * @deprecated Use getForwardingHint.
   */
  public final Link
  getLink() throws EncodingException
  {
    if (link_.get() != null)
      return (Link)link_.get();
    else if (!linkWireEncoding_.isNull()) {
      // Decode the link object from linkWireEncoding_.
      Link link = new Link();
      link.wireDecode(linkWireEncoding_, linkWireEncodingFormat_);
      link_.set(link);

      // Clear linkWireEncoding_ since it is now managed by the link object.
      linkWireEncoding_ = new Blob();
      linkWireEncodingFormat_ = null;

      return link;
    }
    else
      return null;
  }

  /**
   * Get the wire encoding of the link object. If there is already a wire
   * encoding then return it. Otherwise encode from the link object (if
   * available).
   * @param wireFormat The desired wire format for the encoding.
   * @return The wire encoding, or an isNull Blob if the link is not specified.
   * @throws EncodingException for error encoding the link object.
   * @deprecated Use getForwardingHint.
   */
  public final Blob
  getLinkWireEncoding(WireFormat wireFormat) throws EncodingException
  {
    if (!linkWireEncoding_.isNull() && linkWireEncodingFormat_ == wireFormat)
      return linkWireEncoding_;

    Link link = getLink();
    if (link != null)
      return link.wireEncode(wireFormat);
    else
      return new Blob();
  }

  /**
   * Get the wire encoding of the link object. If there is already a wire
   * encoding then return it. Otherwise encode from the link object (if
   * available).
   * @return The wire encoding, or an isNull Blob if the link is not specified.
   * @throws EncodingException for error encoding the link object.
   * @deprecated Use getForwardingHint.
   */
  public final Blob
  getLinkWireEncoding() throws EncodingException
  {
    return getLinkWireEncoding(WireFormat.getDefaultWireFormat());
  }

  /**
   * Get the selected delegation index.
   * @return The selected delegation index. If not specified, return -1.
   * @deprecated Use getForwardingHint.
   */
  public final int
  getSelectedDelegationIndex() { return selectedDelegationIndex_; }

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
   * Set the interest name.
   * @note You can also call getName and change the name values directly.
   * @param name The interest name. This makes a copy of the name.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setName(Name name)
  {
    name_.set(name == null ? new Name() : new Name(name));
    ++changeCount_;
    return this;
  }

  /**
   * Set the min suffix components count.
   * @param minSuffixComponents The min suffix components count. If not
   * specified, set to -1.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setMinSuffixComponents(int minSuffixComponents)
  {
    minSuffixComponents_ = minSuffixComponents;
    ++changeCount_;
    return this;
  }

  /**
   * Set the max suffix components count.
   * @param maxSuffixComponents The max suffix components count. If not
   * specified, set to -1.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setMaxSuffixComponents(int maxSuffixComponents)
  {
    maxSuffixComponents_ = maxSuffixComponents;
    ++changeCount_;
    return this;
  }

  /**
   * Set the CanBePrefix flag.
   * @param canBePrefix True if the Interest name can be a prefix. If you do not
   * set this flag, the default value is true.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setCanBePrefix(boolean canBePrefix)
  {
    // Use the closest v0.2 semantics. CanBePrefix is the opposite of exact
    // match where MaxSuffixComponents is 1 (for the implicit digest).
    maxSuffixComponents_ = (canBePrefix ? -1 : 1);
    ++changeCount_;
    return this;
  }

  /**
   * Set the child selector.
   * @param childSelector The child selector. If not specified, set to -1.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setChildSelector(int childSelector)
  {
    childSelector_ = childSelector;
    ++changeCount_;
    return this;
  }

  /**
   * Set the MustBeFresh flag.
   * @param mustBeFresh True if the content must be fresh, otherwise false. If
   * you do not set this flag, the default value is true.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setMustBeFresh(boolean mustBeFresh)
  {
    mustBeFresh_ = mustBeFresh;
    ++changeCount_;
    return this;
  }

  /**
   * Set the interest lifetime.
   * @param interestLifetimeMilliseconds The interest lifetime in milliseconds.
   * If not specified, set to -1.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setInterestLifetimeMilliseconds(double interestLifetimeMilliseconds)
  {
    interestLifetimeMilliseconds_ = interestLifetimeMilliseconds;
    ++changeCount_;
    return this;
  }

  /**
   * @deprecated You should let the wire encoder generate a random nonce
   * internally before sending the interest.
   */
  public final Interest
  setNonce(Blob nonce)
  {
    nonce_ = (nonce == null ? new Blob() : nonce);
    // Set getNonceChangeCount_ so that the next call to getNonce() won't
    //   clear nonce_.
    ++changeCount_;
    getNonceChangeCount_ = getChangeCount();
    return this;
  }

  /**
   * Set this interest to use a copy of the given KeyLocator object.
   * @note You can also call getKeyLocator and change the key locator directly.
   * @param keyLocator The KeyLocator object. This makes a copy of the object.
   * If no key locator is specified, set to a new default KeyLocator(), or to a
   * KeyLocator with an unspecified type.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setKeyLocator(KeyLocator keyLocator)
  {
    keyLocator_.set(keyLocator == null ? new KeyLocator() : new KeyLocator(keyLocator));
    ++changeCount_;
    return this;
  }

  /**
   * Set this interest to use a copy of the given Exclude object.
   * @note You can also call getExclude and change the exclude entries directly.
   * @param exclude The Exclude object. This makes a copy of the object. If no
   * exclude is specified, set to a new default Exclude(), or to an Exclude with
   * size() 0.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setExclude(Exclude exclude)
  {
    exclude_.set(exclude == null ? new Exclude() : new Exclude(exclude));
    ++changeCount_;
    return this;
  }

  /**
   * Set this interest to use a copy of the given DelegationSet object as the
   * forwarding hint.
   * @note You can also call getForwardingHint and change the forwarding hint
   * directly.
   * @param forwardingHint The DelegationSet object to use as the forwarding
   * hint. This makes a copy of the object. If no forwarding hint is specified,
   * set to a new default DelegationSet() with no entries.
   * @return This Interest so that you can chain calls to update values.
   */
  public final Interest
  setForwardingHint(DelegationSet forwardingHint)
  {
    forwardingHint_.set(forwardingHint == null ?
      new DelegationSet() : new DelegationSet(forwardingHint));
    ++changeCount_;
    return this;
  }

  /**
   * Set the link wire encoding bytes, without decoding them. If there is
   * a link object, set it to null. If you later call getLink(), it will
   * decode the wireEncoding to create the link object.
   * @param encoding The buffer with the bytes of the link wire encoding.
   * If no link is specified, set to an empty Blob() or call unsetLink().
   * @param wireFormat The wire format of the encoding, to be used later if
   * necessary to decode.
   * @return This Interest so that you can chain calls to update values.
   * @deprecated Use setForwardingHint.
   */
  public final Interest
  setLinkWireEncoding(Blob encoding, WireFormat wireFormat)
  {
    linkWireEncoding_ = encoding;
    linkWireEncodingFormat_ = wireFormat;

    // Clear the link object, assuming that it has a different encoding.
    link_.set(null);

    ++changeCount_;
    return this;
  }

  /**
   * Set the link wire encoding bytes, without decoding them. If there is
   * a link object, set it to null. IF you later call getLink(), it will
   * decode the wireEncoding to create the link object.
   * @param encoding The buffer with the bytes of the link wire encoding.
   * If no link is specified, set to an empty Blob().
   * @return This Interest so that you can chain calls to update values.
   * @deprecated Use setForwardingHint.
   */
  public final Interest
  setLinkWireEncoding(Blob encoding)
  {
    return setLinkWireEncoding(encoding, WireFormat.getDefaultWireFormat());
  }

  /**
   * Clear the link wire encoding and link object so that getLink() returns null.
   * @return This Interest so that you can chain calls to update values.
   * @deprecated Use setForwardingHint.
   */
  public final Interest
  unsetLink()
  {
    return setLinkWireEncoding(new Blob(), null);
  }

  /**
   * Set the selected delegation index.
   * @param selectedDelegationIndex The selected delegation index. If not
   * specified, set to -1.
   * @return This Interest so that you can chain calls to update values.
   * @deprecated Use setForwardingHint.
   */
  public final Interest
  setSelectedDelegationIndex(int selectedDelegationIndex)
  {
    selectedDelegationIndex_ = selectedDelegationIndex;
    ++changeCount_;
    return this;
  }

  /**
   * An internal library method to set the LpPacket for an incoming packet. The
   * application should not call this.
   * @param lpPacket The LpPacket. This does not make a copy.
   * @return This Interest so that you can chain calls to update values.
   * @note This is an experimental feature. This API may change in the future.
   */
  final Interest
  setLpPacket(LpPacket lpPacket)
  {
    lpPacket_ = lpPacket;
    // Don't update changeCount_ since this doesn't affect the wire encoding.
    return this;
  }

  /**
   * Update the bytes of the nonce with new random values. This ensures that the
   * new nonce value is different than the current one. If the current nonce is
   * not specified, this does nothing.
   */
  public final void
  refreshNonce()
  {
    Blob currentNonce = getNonce();
    if (currentNonce.size() == 0)
      return;

    ByteBuffer newNonce = ByteBuffer.allocate(currentNonce.size());
    while (true) {
      random_.nextBytes(newNonce.array());
      if (!newNonce.equals(currentNonce.buf()))
        break;
    }

    nonce_ = new Blob(newNonce, false);
    // Set getNonceChangeCount_ so that the next call to getNonce() won't clear
    // nonce_.
    ++changeCount_;
    getNonceChangeCount_ = getChangeCount();
  }

  /**
   * Check if this Interest's name matches the given name (using Name.match)
   * and the given name also conforms to the interest selectors.
   * @param name The name to check.
   * @return True if the name and interest selectors match, otherwise false.
   */
  public final boolean
  matchesName(Name name)
  {
    if (!getName().match(name))
      return false;

    if (minSuffixComponents_ >= 0 &&
        // Add 1 for the implicit digest.
        !(name.size() + 1 - getName().size() >= minSuffixComponents_))
      return false;
    if (maxSuffixComponents_ >= 0 &&
        // Add 1 for the implicit digest.
        !(name.size() + 1 - getName().size() <= maxSuffixComponents_))
      return false;
    if (getExclude().size() > 0 && name.size() > getName().size() &&
        getExclude().matches(name.get(getName().size())))
      return false;

    return true;
  }

  /**
   * Check if the given Data packet can satisfy this Interest. This method
   * considers the Name, MinSuffixComponents, MaxSuffixComponents,
   * PublisherPublicKeyLocator, and Exclude. It does not consider the
   * ChildSelector or MustBeFresh. This uses the given wireFormat to get the
   * Data packet encoding for the full Name.
   * @param data The Data packet to check.
   * @param wireFormat A WireFormat object used to encode the Data packet to
   * get its full Name.
   * @return True if the given Data packet can satisfy this Interest.
   */
  public final boolean
  matchesData(Data data, WireFormat wireFormat) throws EncodingException
  {
    // Imitate ndn-cxx Interest::matchesData.
    int interestNameLength = getName().size();
    Name dataName = data.getName();
    int fullNameLength = dataName.size() + 1;

    // Check MinSuffixComponents.
    boolean hasMinSuffixComponents = getMinSuffixComponents() >= 0;
    int minSuffixComponents =
      hasMinSuffixComponents ? getMinSuffixComponents() : 0;
    if (!(interestNameLength + minSuffixComponents <= fullNameLength))
      return false;

    // Check MaxSuffixComponents.
    boolean hasMaxSuffixComponents = getMaxSuffixComponents() >= 0;
    if (hasMaxSuffixComponents &&
        !(interestNameLength + getMaxSuffixComponents() >= fullNameLength))
      return false;

    // Check the prefix.
    if (interestNameLength == fullNameLength) {
      if (getName().get(-1).isImplicitSha256Digest()) {
        if (!getName().equals(data.getFullName(wireFormat)))
          return false;
      }
      else
        // The Interest Name is the same length as the Data full Name, but the
        //   last component isn't a digest so there's no possibility of matching.
        return false;
    }
    else {
      // The Interest Name should be a strict prefix of the Data full Name,
      if (!getName().isPrefixOf(dataName))
        return false;
    }

    // Check the Exclude.
    // The Exclude won't be violated if the Interest Name is the same as the
    //   Data full Name.
    if (getExclude().size() > 0 && fullNameLength > interestNameLength) {
      if (interestNameLength == fullNameLength - 1) {
        // The component to exclude is the digest.
        if (getExclude().matches
            (data.getFullName(wireFormat).get(interestNameLength)))
          return false;
      }
      else {
        // The component to exclude is not the digest.
        if (getExclude().matches(dataName.get(interestNameLength)))
          return false;
      }
    }

    // Check the KeyLocator.
    KeyLocator publisherPublicKeyLocator = getKeyLocator();
    if (publisherPublicKeyLocator.getType() != KeyLocatorType.NONE) {
      Signature signature = data.getSignature();
      if (!KeyLocator.canGetFromSignature(signature))
        // No KeyLocator in the Data packet.
        return false;
      if (!publisherPublicKeyLocator.equals
          (KeyLocator.getFromSignature(signature)))
        return false;
    }

    return true;
  }

  /**
   * Check if the given Data packet can satisfy this Interest. This method
   * considers the Name, MinSuffixComponents, MaxSuffixComponents,
   * PublisherPublicKeyLocator, and Exclude. It does not consider the
   * ChildSelector or MustBeFresh. This uses the default WireFormat to get the
   * Data packet encoding for the full Name.
   * @param data The Data packet to check.
   * @return True if the given Data packet can satisfy this Interest.
   */
  public final boolean
  matchesData(Data data) throws EncodingException
  {
    return matchesData(data, WireFormat.getDefaultWireFormat());
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
   * Get the change count, which is incremented each time this object
   * (or a child object) is changed.
   * @return The change count.
   */
  public final long
  getChangeCount()
  {
    // Make sure each of the checkChanged is called.
    boolean changed = name_.checkChanged();
    changed = keyLocator_.checkChanged() || changed;
    changed = exclude_.checkChanged() || changed;
    changed = forwardingHint_.checkChanged() || changed;
    changed = link_.checkChanged() || changed;
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

  private final ChangeCounter name_ = new ChangeCounter(new Name());
  private int minSuffixComponents_ = -1;
  private int maxSuffixComponents_ = -1;
  private final ChangeCounter keyLocator_ = new ChangeCounter(new KeyLocator());
  private final ChangeCounter exclude_ = new ChangeCounter(new Exclude());
  private int childSelector_ = -1;
  private boolean mustBeFresh_ = true;
  private double interestLifetimeMilliseconds_ = -1;
  private Blob nonce_ = new Blob();
  private long getNonceChangeCount_ = 0;
  private LpPacket lpPacket_ = null;
  private Blob linkWireEncoding_ = new Blob();
  private WireFormat linkWireEncodingFormat_ = null;
  private final ChangeCounter forwardingHint_ =
    new ChangeCounter(new DelegationSet());
  private final ChangeCounter link_ = new ChangeCounter(null);
  private int selectedDelegationIndex_ = -1;
  private SignedBlob defaultWireEncoding_ = new SignedBlob();
  private WireFormat defaultWireEncodingFormat_;
  private long getDefaultWireEncodingChangeCount_ = 0;
  private long changeCount_ = 0;
  private static final Random random_ = new Random();
}
