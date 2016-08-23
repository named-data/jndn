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
import java.util.ArrayList;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.encoding.tlv.TlvEncoder;

/**
 * A Name holds an array of Name.Component and represents an NDN name.
 */
public class Name implements ChangeCountable, Comparable {
  /**
   * A Name.Component holds a read-only name component value.
   */
  public static class Component implements Comparable {
    /**
     * Create a new GENERIC Name.Component with a zero-length value.
     */
    public
    Component()
    {
      value_ = new Blob(ByteBuffer.allocate(0), false);
      type_ = ComponentType.GENERIC;
    }

    /**
     * Create a new GENERIC Name.Component, using the existing the Blob value.
     * (To create an ImplicitSha256Digest component, use fromImplicitSha256Digest.)
     * @param value The component value.  value may not be null, but
     * value.buf() may be null.
     */
    public
    Component(Blob value)
    {
      if (value == null)
        throw new NullPointerException("Component: Blob value may not be null");
      value_ = value;
      type_ = ComponentType.GENERIC;
    }

    /**
     * Create a new Name.Component, taking another pointer to the component's
     * read-only value.
     * @param component The component to copy.
     */
    public
    Component(Component component)
    {
      value_ = component.value_;
      type_ = component.type_;
    }

    /**
     * Create a new GENERIC Name.Component, copying the given value.
     * (To create an ImplicitSha256Digest component, use fromImplicitSha256Digest.)
     * @param value The value byte array.
     */
    public
    Component(byte[] value)
    {
      value_ = new Blob(value, true);
      type_ = ComponentType.GENERIC;
    }

    /**
     * Create a new GENERIC Name.Component, converting the value to UTF8 bytes.
     * Note, this does not escape %XX values.  If you need to escape, use
     * Name.fromEscapedString.
     * @param value The string to convert to UTF8.
     */
    public
    Component(String value)
    {
      value_ = new Blob(value);
      type_ = ComponentType.GENERIC;
    }

    /**
     * Get the component value.
     * @return The component value.
     */
    public final Blob
    getValue() { return value_; }

    /**
     * Write this component value to result, escaping characters according to
     * the NDN URI Scheme. This also adds "..." to a value with zero or more ".".
     * This adds a type code prefix as needed, such as "sha256digest=".
     * @param result The StringBuffer to write to.
     */
    public final void
    toEscapedString(StringBuffer result)
    {
      if (type_ == ComponentType.IMPLICIT_SHA256_DIGEST) {
        result.append("sha256digest=");
        Blob.toHex(value_.buf(), result);
      }
      else
        Name.toEscapedString(value_.buf(), result);
    }

    /**
     * Convert this component value by escaping characters according to the
     * NDN URI Scheme. This also adds "..." to a value with zero or more ".".
     * This adds a type code prefix as needed, such as "sha256digest=".
     * @return The escaped string.
     */
    public final String
    toEscapedString()
    {
      StringBuffer result = new StringBuffer(value_.buf().remaining());
      toEscapedString(result);
      return result.toString();
    }

    /**
     * Check if this component is a segment number according to NDN naming
     * conventions for "Segment number" (marker 0x00).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return True if this is a segment number.
     */
    public final boolean
    isSegment()
    {
      return value_.size() >= 1 && value_.buf().get(0) == (byte)0x00 && isGeneric();
    }

    /**
     * Check if this component is a segment byte offset according to NDN
     * naming conventions for segment "Byte offset" (marker 0xFB).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return True if this is a segment byte offset.
     */
    public final boolean
    isSegmentOffset()
    {
      return value_.size() >= 1 && value_.buf().get(0) == (byte)0xFB && isGeneric();
    }

    /**
     * Check if this component is a version number according to NDN naming
     * conventions for "Versioning" (marker 0xFD).
     * @return True if this is a version number.
     */
    public final boolean
    isVersion()
    {
      return value_.size() >= 1 && value_.buf().get(0) == (byte)0xFD && isGeneric();
    }

    /**
     * Check if this component is a timestamp according to NDN naming
     * conventions for "Timestamp" (marker 0xFC).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return True if this is a timestamp.
     */
    public final boolean
    isTimestamp()
    {
      return value_.size() >= 1 && value_.buf().get(0) == (byte)0xFC && isGeneric();
    }

    /**
     * Check if this component is a sequence number according to NDN naming
     * conventions for "Sequencing" (marker 0xFE).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return True if this is a sequence number.
     */
    public final boolean
    isSequenceNumber()
    {
      return value_.size() >= 1 && value_.buf().get(0) == (byte)0xFE && isGeneric();
    }

    /**
     * Check if this component is a generic component.
     * @return True if this is an generic component.
     */
    public final boolean
    isGeneric()
    {
      return type_ == ComponentType.GENERIC;
    }

    /**
     * Check if this component is an ImplicitSha256Digest component.
     * @return True if this is an ImplicitSha256Digest component.
     */
    public final boolean
    isImplicitSha256Digest()
    {
      return type_ == ComponentType.IMPLICIT_SHA256_DIGEST;
    }

    /**
     * Interpret this name component as a network-ordered number and return an
     * integer.
     * @return The integer number.
     */
    public final long
    toNumber()
    {
      ByteBuffer buffer = value_.buf();
      if (buffer == null)
        return 0;

      long result = 0;
      for (int i = buffer.position(); i < buffer.limit(); ++i) {
        result *= 256;
        result += (long)((int)buffer.get(i) & 0xff);
      }

      return result;
    }

    /**
     * Interpret this name component as a network-ordered number with a marker
     * and return an integer.
     * @param marker The required first byte of the component.
     * @return The integer number.
     * @throws EncodingException If the first byte of the component does not
     * equal the marker.
     */
    public final long
    toNumberWithMarker(int marker) throws EncodingException
    {
      ByteBuffer buffer = value_.buf();
      if (buffer == null || buffer.remaining() <= 0 || buffer.get(0) != (byte)marker)
        throw new EncodingException
          ("Name component does not begin with the expected marker.");

      long result = 0;
      for (int i = buffer.position() + 1; i < buffer.limit(); ++i) {
        result *= 256;
        result += (long)((int)buffer.get(i) & 0xff);
      }

      return result;
    }

    /**
     * Interpret this name component as a segment number according to NDN naming
     * conventions for "Segment number" (marker 0x00).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return The integer segment number.
     * @throws EncodingException If the first byte of the component is not the
     * expected marker.
     */
    public final long
    toSegment() throws EncodingException
    {
      return toNumberWithMarker(0x00);
    }

    /**
     * Interpret this name component as a segment byte offset according to NDN
     * naming conventions for segment "Byte offset" (marker 0xFB).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return The integer segment byte offset.
     * @throws EncodingException If the first byte of the component is not the
     * expected marker.
     */
    public final long
    toSegmentOffset() throws EncodingException
    {
      return toNumberWithMarker(0xFB);
    }

    /**
     * Interpret this name component as a version number  according to NDN naming
     * conventions for "Versioning" (marker 0xFD). Note that this returns
     * the exact number from the component without converting it to a time
     * representation.
     * @return The integer version number.
     * @throws EncodingException If the first byte of the component is not the
     * expected marker.
     */
    public final long
    toVersion() throws EncodingException
    {
      return toNumberWithMarker(0xFD);
    }

    /**
     * Interpret this name component as a timestamp  according to NDN naming
     * conventions for "Timestamp" (marker 0xFC).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return The number of microseconds since the UNIX epoch (Thursday,
     * 1 January 1970) not counting leap seconds.
     * @throws EncodingException If the first byte of the component is not the
     * expected marker.
     */
    public final long
    toTimestamp() throws EncodingException
    {
      return toNumberWithMarker(0xFC);
    }

    /**
     * Interpret this name component as a sequence number according to NDN naming
     * conventions for "Sequencing" (marker 0xFE).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @return The integer sequence number.
     * @throws EncodingException If the first byte of the component is not the
     * expected marker.
     */
    public final long
    toSequenceNumber() throws EncodingException
    {
      return toNumberWithMarker(0xFE);
    }

    /**
     * Create a component whose value is the nonNegativeInteger encoding of the
     * number.
     * @param number The number to be encoded.
     * @return The component value.
     */
    public static Component
    fromNumber(long number)
    {
      if (number < 0)
        number = 0;

      TlvEncoder encoder = new TlvEncoder(8);
      encoder.writeNonNegativeInteger(number);
      return new Component(new Blob(encoder.getOutput(), false));
    }

    /**
     * Create a component whose value is the marker appended with the
     * nonNegativeInteger encoding of the number.
     * @param number The number to be encoded.
     * @param marker The marker to use as the first byte of the component.
     * @return The component value.
     */
    public static Component
    fromNumberWithMarker(long number, int marker)
    {
      if (number < 0)
        number = 0;

      TlvEncoder encoder = new TlvEncoder(9);
      // Encode backwards.
      encoder.writeNonNegativeInteger(number);
      encoder.writeNonNegativeInteger((long)marker);
      return new Component(new Blob(encoder.getOutput(), false));
    }

    /**
     * Create a component with the encoded segment number according to NDN
     * naming conventions for "Segment number" (marker 0x00).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @param segment The segment number.
     * @return The new Component.
     */
    public static Component
    fromSegment(long segment)
    {
      return fromNumberWithMarker(segment, 0x00);
    }

    /**
     * Create a component with the encoded segment byte offset according to NDN
     * naming conventions for segment "Byte offset" (marker 0xFB).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @param segmentOffset The segment byte offset.
     * @return The new Component.
     */
    public static Component
    fromSegmentOffset(long segmentOffset)
    {
      return fromNumberWithMarker(segmentOffset, 0xFB);
    }

    /**
     * Create a component with the encoded version number according to NDN
     * naming conventions for "Versioning" (marker 0xFD).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * Note that this encodes the exact value of version without converting from a
     * time representation.
     * @param version The version number.
     * @return The new Component.
     */
    public static Component
    fromVersion(long version)
    {
      return fromNumberWithMarker(version, 0xFD);
    }

    /**
     * Create a component with the encoded timestamp according to NDN naming
     * conventions for "Timestamp" (marker 0xFC).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @param timestamp The number of microseconds since the UNIX epoch (Thursday,
     * 1 January 1970) not counting leap seconds.
     * @return The new Component.
     */
    public static Component
    fromTimestamp(long timestamp)
    {
      return fromNumberWithMarker(timestamp, 0xFC);
    }

    /**
     * Create a component with the encoded sequence number according to NDN naming
     * conventions for "Sequencing" (marker 0xFE).
     * http://named-data.net/doc/tech-memos/naming-conventions.pdf
     * @param sequenceNumber The sequence number.
     * @return The new Component.
     */
    public static Component
    fromSequenceNumber(long sequenceNumber)
    {
      return fromNumberWithMarker(sequenceNumber, 0xFE);
    }

    /**
     * Create a component of type ImplicitSha256DigestComponent, so that
     * isImplicitSha256Digest() is true.
     * @param digest The SHA-256 digest value.
     * @return The new Component.
     * @throws EncodingException If the digest length is not 32 bytes.
     */
    public static Component
    fromImplicitSha256Digest(Blob digest) throws EncodingException
    {
      if (digest.size() != 32)
        throw new EncodingException
          ("Name.Component.fromImplicitSha256Digest: The digest length must be 32 bytes");

      Component result = new Component(digest);
      result.type_ = ComponentType.IMPLICIT_SHA256_DIGEST;
      return result;
    }

    /**
     * Create a component of type ImplicitSha256DigestComponent, so that
     * isImplicitSha256Digest() is true.
     * @param digest The SHA-256 digest value.
     * @return The new Component.
     * @throws EncodingException If the digest length is not 32 bytes.
     */
    public static Component
    fromImplicitSha256Digest(byte[] digest) throws EncodingException
    {
      return fromImplicitSha256Digest(new Blob(digest));
    }

    /**
     * Get the successor of this component, as described in Name.getSuccessor.
     * @return A new Name.Component which is the successor of this.
     */
    public final Component
    getSuccessor()
    {
      // Allocate an extra byte in case the result is larger.
      ByteBuffer result = ByteBuffer.allocate(value_.size() + 1);

      boolean carry = true;
      for (int i = value_.size() - 1; i >= 0; --i) {
        if (carry) {
          // b & 0xff makes the byte unsigned and returns an int.
          int x = value_.buf().get(value_.buf().position() + i) & 0xff;
          x = (x + 1) & 0xff;
          result.put(i, (byte)x);
          carry = (x == 0);
        }
        else
          result.put(i, value_.buf().get(value_.buf().position() + i));
      }

      if (carry)
        // Assume all the bytes were set to zero (or the component was empty).
        // In NDN ordering, carry does not mean to prepend a 1, but to make a
        // component one byte longer of all zeros.
        result.put(result.limit() - 1, (byte)0);
      else
        // We didn't need the extra byte.
        result.limit(value_.size());

      return new Component(new Blob(result, false));
    }

    /**
     * Check if this is the same component as other.
     * @param other The other Component to compare with.
     * @return True if the components are equal, otherwise false.
     */
    public final boolean
    equals(Component other)
    {
      return value_.equals(other.value_) && type_ == other.type_;
    }

    public boolean
    equals(Object other)
    {
      if (!(other instanceof Component))
        return false;

      return equals((Component)other);
    }

    public int hashCode()
    {
      return 37 * type_.getNumericType() + value_.hashCode();
    }

    /**
     * Compare this to the other Component using NDN canonical ordering.
     * @param other The other Component to compare with.
     * @return 0 If they compare equal, -1 if this comes before other in the
     * canonical ordering, or 1 if this comes after other in the canonical
     * ordering.
     */
    public final int
    compare(Component other)
    {
      if (type_.getNumericType() < other.type_.getNumericType())
        return -1;
      if (type_.getNumericType() > other.type_.getNumericType())
        return 1;

      if (value_.size() < other.value_.size())
        return -1;
      if (value_.size() > other.value_.size())
        return 1;

      // The components are equal length. Just do a byte compare.
      return value_.compare(other.value_);
    }

    public final int
    compareTo(Object o) { return this.compare((Component)o); }

    // Also include this version for portability.
    public final int
    CompareTo(Object o) { return this.compare((Component)o); }

    /**
     * Reverse the bytes in buffer starting at position, up to but not including
     * limit.
     * @param buffer
     * @param position
     * @param limit
     */
    private static void reverse(ByteBuffer buffer, int position, int limit)
    {
      int from = position;
      int to = limit - 1;
      while (from < to) {
        // swap
        byte temp = buffer.get(from);
        buffer.put(from, buffer.get(to));
        buffer.put(to, temp);

        --to;
        ++from;
      }
    }

    /**
     * A ComponentType specifies the recognized types of a name component.
     */
    private enum ComponentType {
      IMPLICIT_SHA256_DIGEST(1),
      GENERIC(8);

      ComponentType(int type)
      {
        type_ = type;
      }

      public final int
      getNumericType() { return type_; }

      private final int type_;
    }

    // Note: We keep the type_ internal because it is only used to distinguish
    // from ImplicitSha256Digest. If we support general typed components then
    // we can provide public access.
    private ComponentType type_;
    private final Blob value_;
  }

  /**
   * Create a new Name with no components.
   */
  public
  Name()
  {
    components_ = new ArrayList<Component>();
  }

  /**
   * Create a new Name with the components in the given name.
   * @param name The name with components to copy from.
   */
  public
  Name(Name name)
  {
    components_ = new ArrayList<Component>(name.components_);
  }

  /**
   * Create a new Name, copying the components.
   * @param components The components to copy.
   */
  public
  Name(ArrayList components)
  {
    // Don't need to deep-copy Component elements because they are read-only.
    components_ = new ArrayList<Component>(components);
  }

  /**
   * Create a new Name, copying the components.
   * @param components The components to copy.
   */
  public
  Name(Component[] components)
  {
    components_ = new ArrayList<Component>();
    for (int i = 0; i < components.length; ++i)
      components_.add(components[i]);
  }

  /**
   * Parse the uri according to the NDN URI Scheme and create the name with the
   * components.
   * @param uri The URI string.
   */
  public
  Name(String uri)
  {
    components_ = new ArrayList<Component>();
    set(uri);
  }

  /**
   * Get the number of components.
   * @return The number of components.
   */
  public final int
  size() { return components_.size(); }

  /**
   * Get the component at the given index.
   * @param i The index of the component, starting from 0. However, if i is
   * negative, return the component at size() - (-i).
   * @return The name component at the index.
   */
  public final Component
  get(int i)
  {
    if (i >= 0)
      return components_.get(i);
    else
      return components_.get(components_.size() - (-i));
  }

  public final void
  set(String uri)
  {
    clear();

    uri = uri.trim();
    if (uri.length() == 0)
      return;

    int iColon = uri.indexOf(':');
    if (iColon >= 0) {
      // Make sure the colon came before a '/'.
      int iFirstSlash = uri.indexOf('/');
      if (iFirstSlash < 0 || iColon < iFirstSlash)
        // Omit the leading protocol such as ndn:
        uri = uri.substring(iColon + 1).trim();
    }

    // Trim the leading slash and possibly the authority.
    if (uri.charAt(0) == '/') {
      if (uri.length() >= 2 && uri.charAt(1) == '/') {
        // Strip the authority following "//".
        int iAfterAuthority = uri.indexOf('/', 2);
        if (iAfterAuthority < 0)
          // Unusual case: there was only an authority.
          return;
        else
          uri = uri.substring(iAfterAuthority + 1).trim();
      }
      else
        uri = uri.substring(1).trim();
    }

    int iComponentStart = 0;

    // Unescape the components.
    String sha256digestPrefix = "sha256digest=";
    while (iComponentStart < uri.length()) {
      int iComponentEnd = uri.indexOf("/", iComponentStart);
      if (iComponentEnd < 0)
        iComponentEnd = uri.length();

      Component component;
      if (sha256digestPrefix.regionMatches
          (0, uri, iComponentStart, sha256digestPrefix.length())) {
        try {
          component = Component.fromImplicitSha256Digest
            (fromHex(uri, iComponentStart + sha256digestPrefix.length(),
                     iComponentEnd));
        } catch (EncodingException ex) {
          throw new Error(ex.getMessage());
        }
      }
      else
        component = new Component
          (fromEscapedString(uri, iComponentStart, iComponentEnd));

      // Ignore illegal components.  This also gets rid of a trailing '/'.
      if (!component.getValue().isNull())
        append(component);

      iComponentStart = iComponentEnd + 1;
    }
  }

  /**
   * Clear all the components.
   */
  public final void
  clear()
  {
    components_.clear();
    ++changeCount_;
  }

  /**
   * Append a new GENERIC component, copying from value.
   * (To append an ImplicitSha256Digest component, use appendImplicitSha256Digest.)
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  append(byte[] value)
  {
    return append(new Component(value));
  }

  /**
   * Append a new GENERIC component, using the existing Blob value.
   * (To append an ImplicitSha256Digest component, use appendImplicitSha256Digest.)
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  append(Blob value)
  {
    return append(new Component(value));
  }

  /**
   * Append the component to this name.
   * @param component The component to append.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  append(Component component)
  {
    components_.add(component);
    ++changeCount_;
    return this;
  }

  public final Name
  append(Name name)
  {
    if (name == this)
      // Copying from this name, so need to make a copy first.
      return append(new Name(name));

    for (int i = 0; i < name.components_.size(); ++i)
      append(name.get(i));

    return this;
  }

  /**
   * Convert the value to UTF8 bytes and append a Name.Component.
   * Note, this does not escape %XX values.  If you need to escape, use
   * Name.fromEscapedString.  Also, if the string has "/", this does not split
   * into separate components.  If you need that then use
   * append(new Name(value)).
   * @param value The string to convert to UTF8.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  append(String value)
  {
    return append(new Component(value));
  }

  /**
   * Get a new name, constructed as a subset of components.
   * @param iStartComponent The index if the first component to get. If
   * iStartComponent is -N then return return components starting from
   * name.size() - N.
   * @param nComponents The number of components starting at iStartComponent.
   * If greater than the size of this name, get until the end of the name.
   * @return A new name.
   */
  public final Name
  getSubName(int iStartComponent, int nComponents)
  {
    if (iStartComponent < 0)
      iStartComponent = components_.size() - (-iStartComponent);

    Name result = new Name();

    int iEnd = iStartComponent + nComponents;
    for (int i = iStartComponent; i < iEnd && i < components_.size(); ++i)
      result.components_.add(components_.get(i));

    return result;
  }

  /**
   * Get a new name, constructed as a subset of components starting at
   * iStartComponent until the end of the name.
   * @param iStartComponent The index if the first component to get. If
   * iStartComponent is -N then return return components starting from
   * name.size() - N.
   * @return A new name.
   */
  public final Name
  getSubName(int iStartComponent)
  {
    return getSubName(iStartComponent, components_.size());
  }

  /**
   * Return a new Name with the first nComponents components of this Name.
   * @param nComponents The number of prefix components.  If nComponents is -N
   * then return the prefix up to name.size() - N. For example getPrefix(-1)
   * returns the name without the final component.
   * @return A new Name.
   */
  public final Name
  getPrefix(int nComponents)
  {
    if (nComponents < 0)
      return getSubName(0, components_.size() + nComponents);
    else
      return getSubName(0, nComponents);
  }

  /**
   * Encode this name as a URI according to the NDN URI Scheme.
   * @param includeScheme If true, include the "ndn:" scheme in the URI, e.g.
   * "ndn:/example/name". If false, just return the path, e.g. "/example/name",
   * which is normally the case where toUri() is used for display.
   * @return The URI string.
   */
  public final String
  toUri(boolean includeScheme)
  {
    if (components_.isEmpty())
      return includeScheme ? "ndn:/" : "/";

    StringBuffer result = new StringBuffer();
    if (includeScheme)
      result.append("ndn:");
    for (int i = 0; i < components_.size(); ++i) {
      result.append("/");
      get(i).toEscapedString(result);
    }

    return result.toString();
  }

  /**
   * Encode this name as a URI according to the NDN URI Scheme. Just return the
   * path, e.g. "/example/name" which is the default case where toUri() is used
   * for display.
   * @return The URI string.
   */
  public final String
  toUri()
  {
    return toUri(false);
  }

  public String toString() { return toUri(); }

  /**
   * Append a component with the encoded segment number according to NDN
   * naming conventions for "Segment number" (marker 0x00).
   * http://named-data.net/doc/tech-memos/naming-conventions.pdf
   * @param segment The segment number.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendSegment(long segment)
  {
    return append(Component.fromSegment(segment));
  }

  /**
   * Append a component with the encoded segment byte offset according to NDN
   * naming conventions for segment "Byte offset" (marker 0xFB).
   * http://named-data.net/doc/tech-memos/naming-conventions.pdf
   * @param segmentOffset The segment byte offset.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendSegmentOffset(long segmentOffset)
  {
    return append(Component.fromSegmentOffset(segmentOffset));
  }

  /**
   * Append a component with the encoded version number according to NDN
   * naming conventions for "Versioning" (marker 0xFD).
   * http://named-data.net/doc/tech-memos/naming-conventions.pdf
   * Note that this encodes the exact value of version without converting from a
   * time representation.
   * @param version The version number.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendVersion(long version)
  {
    return append(Component.fromVersion(version));
  }

  /**
   * Append a component with the encoded timestamp according to NDN naming
   * conventions for "Timestamp" (marker 0xFC).
   * http://named-data.net/doc/tech-memos/naming-conventions.pdf
   * @param timestamp The number of microseconds since the UNIX epoch (Thursday,
   * 1 January 1970) not counting leap seconds.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendTimestamp(long timestamp)
  {
    return append(Component.fromTimestamp(timestamp));
  }

  /**
   * Append a component with the encoded sequence number according to NDN naming
   * conventions for "Sequencing" (marker 0xFE).
   * http://named-data.net/doc/tech-memos/naming-conventions.pdf
   * @param sequenceNumber The sequence number.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendSequenceNumber(long sequenceNumber)
  {
    return append(Component.fromSequenceNumber(sequenceNumber));
  }

  /**
   * Append a component of type ImplicitSha256DigestComponent, so that
   * isImplicitSha256Digest() is true.
   * @param digest The SHA-256 digest value.
   * @return This name so that you can chain calls to append.
   * @throws EncodingException If the digest length is not 32 bytes.
   */
  public final Name
  appendImplicitSha256Digest(Blob digest) throws EncodingException
  {
    return append(Component.fromImplicitSha256Digest(digest));
  }

  /**
   * Append a component of type ImplicitSha256DigestComponent, so that
   * isImplicitSha256Digest() is true.
   * @param digest The SHA-256 digest value.
   * @return This name so that you can chain calls to append.
   * @throws EncodingException If the digest length is not 32 bytes.
   */
  public final Name
  appendImplicitSha256Digest(byte[] digest) throws EncodingException
  {
    return append(Component.fromImplicitSha256Digest(digest));
  }

  /**
   * Check if this name has the same component count and components as the given
   * name.
   * @param name The Name to check.
   * @return true if the names are equal, otherwise false.
   */
  public boolean
  equals(Name name)
  {
    if (components_.size() != name.components_.size())
      return false;

    // Check from last to first since the last components are more likely to differ.
    for (int i = components_.size() - 1; i >= 0; --i) {
      if (!get(i).getValue().equals(name.get(i).getValue()))
        return false;
    }

    return true;
  }

  public boolean
  equals(Object other)
  {
    if (!(other instanceof Name))
      return false;

    return equals((Name)other);
  }

  public int hashCode()
  {
    if (hashCodeChangeCount_ != getChangeCount()) {
      // The values have changed, so the previous hash code is invalidated.
      haveHashCode_ = false;
      hashCodeChangeCount_ = getChangeCount();
    }

    if (!haveHashCode_) {
      int hashCode = 0;
      // Use a similar hash code algorithm as String.
      for (int i = 0; i < components_.size(); ++i)
        hashCode = 37 * hashCode + components_.get(i).hashCode();

      hashCode_ = hashCode;
      haveHashCode_ = true;
    }

    return hashCode_;
  }

  /**
   * Get the successor of this name which is defined as follows.
   *
   *     N represents the set of NDN Names, and X,Y ∈ N.
   *     Operator &lt; is defined by the NDN canonical order on N.
   *     Y is the successor of X, if (a) X &lt; Y, and (b) ∄ Z ∈ N s.t. X &lt; Z &lt; Y.
   *
   * In plain words, the successor of a name is the same name, but with its last
   * component advanced to a next possible value.
   *
   * Examples:
   *
   * - The successor of / is /%00
   * - The successor of /%00%01/%01%02 is /%00%01/%01%03
   * - The successor of /%00%01/%01%FF is /%00%01/%02%00
   * - The successor of /%00%01/%FF%FF is /%00%01/%00%00%00
   *
   * @return A new name which is the successor of this.
   */
  public final Name
  getSuccessor()
  {
    if (size() == 0) {
      // Return "/%00".
      Name result = new Name();
      result.append(new byte[1]);
      return result;
    }
    else
      return getPrefix(-1).append(get(-1).getSuccessor());
  }

  /**
   * Check if the N components of this name are the same as the first N
   * components of the given name.
   * @param name The Name to check.
   * @return true if this matches the given name, otherwise false.  This always
   * returns true if this name is empty.
   */
  public final boolean
  match(Name name)
  {
    // This name is longer than the name we are checking it against.
    if (components_.size() > name.components_.size())
      return false;

    // Check if at least one of given components doesn't match. Check from last
    // to first since the last components are more likely to differ.
    for (int i = components_.size() - 1; i >= 0; --i) {
      if (!get(i).getValue().equals(name.get(i).getValue()))
        return false;
    }

    return true;
  }

  /**
   * Check if the N components of this name are the same as the first N
   * components of the given name.
   * @param name The Name to check.
   * @return true if this matches the given name, otherwise false.  This always
   * returns true if this name is empty.
   */
  public final boolean
  isPrefixOf(Name name) { return match(name); }

  /**
   * Encode this Name for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this Name.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeName(this);
  }

  /**
   * Encode this Name for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this Name.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeName(this, input, true);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Name.
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
   * Decode the input using a particular wire format and update this Name.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeName(this, input.buf(), false);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this Name.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Compare this to the other Name using NDN canonical ordering.  If the first
   * components of each name are not equal, this returns -1 if the first comes
   * before the second using the NDN canonical ordering for name components, or
   * 1 if it comes after. If they are equal, this compares the second components
   * of each name, etc.  If both names are the same up to the size of the
   * shorter name, this returns -1 if the first name is shorter than the second
   * or 1 if it is longer.  For example, sorted gives:
   * /a/b/d /a/b/cc /c /c/a /bb .  This is intuitive because all names with the
   * prefix /a are next to each other.  But it may be also be counter-intuitive
   * because /c comes before /bb according to NDN canonical ordering since it is
   * shorter.
   * @param other The other Name to compare with.
   * @return 0 If they compare equal, -1 if this Name comes before other in the
   * canonical ordering, or 1 if this Name comes after other in the canonical
   * ordering.
   *
   * See http://named-data.net/doc/0.2/technical/CanonicalOrder.html
   */
  public final int
  compare(Name other)
  {
    return compare(0, components_.size(), other);
  }

  /**
   * Compare a subset of this name to a subset of the other name, equivalent to
   * this.getSubName(iStartComponent, nComponents).compare
   * (other.getSubName(iOtherStartComponent, nOtherComponents)).
   * @param iStartComponent The index if the first component of this name to
   * compare. If iStartComponent is -N then compare components starting from
   * name.size() - N.
   * @param nComponents The number of components starting at iStartComponent.
   * If greater than the size of this name, compare until the end of the name.
   * @param other The other Name to compare with.
   * @param iOtherStartComponent The index if the first component of the other
   * name to compare. If iOtherStartComponent is -N then compare components
   * starting from other.size() - N.
   * @param nOtherComponents The number of components starting at
   * iOtherStartComponent. If greater than the size of the other name, compare
   * until the end of the name.
   * @return 0 If the sub names compare equal, -1 if this sub name comes before
   * the other sub name in the canonical ordering, or 1 if after.
   */
  public final int
  compare
    (int iStartComponent, int nComponents, Name other,
     int iOtherStartComponent, int nOtherComponents)
  {
    if (iStartComponent < 0)
      iStartComponent = size() - (-iStartComponent);
    if (iOtherStartComponent < 0)
      iOtherStartComponent = other.size() - (-iOtherStartComponent);

    nComponents = Math.min(nComponents, size() - iStartComponent);
    nOtherComponents = Math.min(nOtherComponents, other.size() - iOtherStartComponent);

    int count = Math.min(nComponents, nOtherComponents);
    for (int i = 0; i < count; ++i) {
      int comparison = components_.get(iStartComponent + i).compare
        (other.components_.get(iOtherStartComponent + i));
      if (comparison == 0)
        // The components at this index are equal, so check the next components.
        continue;

      // Otherwise, the result is based on the components at this index.
      return comparison;
    }

    // The components up to min(this.size(), other.size()) are equal, so the
    //   shorter name is less.
    if (nComponents < nOtherComponents)
      return -1;
    else if (nComponents > nOtherComponents)
      return 1;
    else
      return 0;
  }

  /**
   * Compare a subset of this name to a subset of the other name, equivalent to
   * this.getSubName(iStartComponent, nComponents).compare
   * (other.getSubName(iOtherStartComponent)), getting all components of other
   * from iOtherStartComponent to the end of the name.
   * @param iStartComponent The index if the first component of this name to
   * compare. If iStartComponent is -N then compare components starting from
   * name.size() - N.
   * @param nComponents The number of components starting at iStartComponent.
   * If greater than the size of this name, compare until the end of the name.
   * @param other The other Name to compare with.
   * @param iOtherStartComponent The index if the first component of the other
   * name to compare. If iOtherStartComponent is -N then compare components
   * starting from other.size() - N.
   * @return 0 If the sub names compare equal, -1 if this sub name comes before
   * the other sub name in the canonical ordering, or 1 if after.
   */
  public final int
  compare
    (int iStartComponent, int nComponents, Name other,
     int iOtherStartComponent)
  {
    return compare
      (iStartComponent, nComponents, other, iOtherStartComponent,
       other.components_.size());
  }

  /**
   * Compare a subset of this name to all of the other name, equivalent to
   * this.getSubName(iStartComponent, nComponents).compare(other).
   * @param iStartComponent The index if the first component of this name to
   * compare. If iStartComponent is -N then compare components starting from
   * name.size() - N.
   * @param nComponents The number of components starting at iStartComponent.
   * If greater than the size of this name, compare until the end of the name.
   * @param other The other Name to compare with.
   * @return 0 If the sub names compare equal, -1 if this sub name comes before
   * the other name in the canonical ordering, or 1 if after.
   */
  public final int
  compare
    (int iStartComponent, int nComponents, Name other)
  {
    return compare
      (iStartComponent, nComponents, other, 0, other.components_.size());
  }

  public final int
  compareTo(Object o) { return this.compare((Name)o); }

  // Also include this version for portability.
  public final int
  CompareTo(Object o) { return this.compare((Name)o); }

  /**
   * Get the change count, which is incremented each time this object is changed.
   * @return The change count.
   */
  public final long
  getChangeCount() { return changeCount_; }

  /**
   * Make a Blob value by decoding the escapedString between beginOffset and
   * endOffset according to the NDN URI Scheme. If the escaped string is
   * "", "." or ".." then return a Blob with a null pointer, which means the
   * component should be skipped in a URI name.
   * This does not check for a type code prefix such as "sha256digest=".
   * @param escapedString The escaped string
   * @param beginOffset The offset in escapedString of the beginning of the
   * portion to decode.
   * @param endOffset The offset in escapedString of the end of the portion to
   * decode.
   * @return The Blob value. If the escapedString is not a valid escaped
   * component, then the Blob has a null pointer.
   */
  public static Blob
  fromEscapedString(String escapedString, int beginOffset, int endOffset)
  {
    String trimmedString =
      escapedString.substring(beginOffset, endOffset).trim();
    ByteBuffer value = unescape(trimmedString);

    // Check for all dots.
    boolean gotNonDot = false;
    for (int i = value.position(); i < value.limit(); ++i) {
      if (value.get(i) != '.') {
        gotNonDot = true;
        break;
      }
    }

    if (!gotNonDot) {
      // Special case for component of only periods.
      if (value.remaining() <= 2)
        // Zero, one or two periods is illegal.  Ignore this component.
        return new Blob();
      else {
        // Remove 3 periods.
        value.position(value.position() + 3);
        return new Blob(value, false);
      }
    }
    else
      return new Blob(value, false);
  }

  /**
   * Make a Blob value by decoding the escapedString according to the NDN URI
   * Scheme.
   * If the escaped string is "", "." or ".." then return a Blob with a null
   * pointer, which means the component should be skipped in a URI name.
   * This does not check for a type code prefix such as "sha256digest=".
   * @param escapedString The escaped string.
   * @return The Blob value. If the escapedString is not a valid escaped
   * component, then the Blob has a null pointer.
   */
  public static Blob
  fromEscapedString(String escapedString)
  {
    return fromEscapedString(escapedString, 0, escapedString.length());
  }

  /**
   * Write the value to result, escaping characters according to the NDN URI
   * Scheme.
   * This also adds "..." to a value with zero or more ".".
   * This does not add a type code prefix such as "sha256digest=".
   * @param value The ByteBuffer with the value.  This reads from position() to
   * limit().
   * @param result The StringBuffer to write to.
   */
  public static void
  toEscapedString(ByteBuffer value, StringBuffer result)
  {
    boolean gotNonDot = false;
    for (int i = value.position(); i < value.limit(); ++i) {
      if (value.get(i) != 0x2e) {
        gotNonDot = true;
        break;
      }
    }
    if (!gotNonDot) {
      // Special case for component of zero or more periods.  Add 3 periods.
      result.append("...");
      for (int i = value.position(); i < value.limit(); ++i)
        result.append('.');
    }
    else {
      for (int i = value.position(); i < value.limit(); ++i) {
        int x = ((int)value.get(i) & 0xff);
        // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
        if (x >= 0x30 && x <= 0x39 || x >= 0x41 && x <= 0x5a ||
          x >= 0x61 && x <= 0x7a || x == 0x2b || x == 0x2d ||
          x == 0x2e || x == 0x5f)
          result.append((char)x);
        else {
          result.append('%');
          if (x < 16)
            result.append('0');
          result.append(Integer.toHexString(x).toUpperCase());
        }
      }
    }
  }

  /**
   * Convert the value by escaping characters according to the NDN URI Scheme.
   * This also adds "..." to a value with zero or more ".".
   * This does not add a type code prefix such as "sha256digest=".
   * @param value The ByteBuffer with the value.  This reads from position() to
   * limit().
   * @return The escaped string.
   */
  public static String
  toEscapedString(ByteBuffer value)
  {
    StringBuffer result = new StringBuffer(value.remaining());
    toEscapedString(value, result);
    return result.toString();
  }

  /**
   * Make a Blob value by decoding the hexString between beginOffset and
   * endOffset.
   * @param hexString The hex string.
   * @param beginOffset The offset in hexString of the beginning of the
   * portion to decode.
   * @param endOffset The offset in hexString of the end of the portion to
   * decode.
   * @return The Blob value. If the hexString is not a valid hex string, then
   * the Blob has a null pointer.
   */
  public static Blob
  fromHex(String hexString, int beginOffset, int endOffset)
  {
    ByteBuffer result = ByteBuffer.allocate((endOffset - beginOffset) / 2);

    for (int i = beginOffset; i < endOffset; ++i) {
      if (hexString.charAt(i) == ' ')
        // Skip whitespace.
        continue;
      if (i + 1 >= endOffset)
        // Only one hex digit. Ignore.
        break;

      int hi = fromHexChar(hexString.charAt(i));
      int lo = fromHexChar(hexString.charAt(i + 1));

      if (hi < 0 || lo < 0)
        // Invalid hex characters.
        return new Blob();

      result.put((byte)(16 * hi + lo));

      // Skip past the second digit.
      i += 1;
    }

    result.flip();
    return new Blob(result, false);
  }

  /**
   * Convert the hex character to an integer from 0 to 15.
   * @param c The hex character.
   * @return The hex value, or -1 if not a hex character.
   */
  private static int
  fromHexChar(char c)
  {
    if (c >= '0' && c <= '9')
      return (int)c - (int)'0';
    else if (c >= 'A' && c <= 'F')
      return (int)c - (int)'A' + 10;
    else if (c >= 'a' && c <= 'f')
      return (int)c - (int)'a' + 10;
    else
      return -1;
  }

  /**
   * Return a copy of str, converting each escaped "%XX" to the char value.
   * @param str The escaped string.
   * @return The unescaped string as a ByteBuffer with position and limit set.
   */
  private static ByteBuffer
  unescape(String str)
  {
    // We know the result will be shorter than the input str.
    ByteBuffer result = ByteBuffer.allocate(str.length());

    for (int i = 0; i < str.length(); ++i) {
      if (str.charAt(i) == '%' && i + 2 < str.length()) {
        int hi = fromHexChar(str.charAt(i + 1));
        int lo = fromHexChar(str.charAt(i + 2));

        if (hi < 0 || lo < 0)
          // Invalid hex characters, so just keep the escaped string.
          result.put((byte)str.charAt(i)).put((byte)str.charAt(i + 1)).put
            ((byte)str.charAt(i + 2));
        else
          result.put((byte)(16 * hi + lo));

        // Skip ahead past the escaped value.
        i += 2;
      }
      else
        // Just copy through.
        result.put((byte)str.charAt(i));
    }

    result.flip();
    return result;
  }

  private final ArrayList<Component> components_;
  private long changeCount_ = 0;
  private boolean haveHashCode_ = false;
  private int hashCode_;
  private long hashCodeChangeCount_ = 0;
}
