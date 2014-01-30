/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;

/**
 * A Name holds an array of Name.Component and represents an NDN name.
 */
public class Name implements ChangeCountable {
  /**
   * A Name.Component holds a read-only name component value.
   */
  public static class Component {
    /**
     * Create a new Name.Component where the Blob buf() pointer is null.
     */
    public 
    Component() 
    {
      value_ = new Blob();
    }
    
    /**
     * Create a new Name.Component, using the existing the Blob value.
     * @param value The component value.  value may not be null, but value.buf() may be null.
     */
    public 
    Component(Blob value)
    {
      if (value == null)
        throw new NullPointerException("Component: Blob value may not be null");
      value_ = value;
    }
    
    /**
     * Create a new Name.Component, copying the given value.
     * @param value The value byte array.
     */
    public 
    Component(byte[] value)
    {
      value_ = new Blob(value);
    }
    
    /**
     * Create a new Name.Component, converting the value to UTF8 bytes.
     * Note, this does not escape %XX values.  If you need to escape, use
     * Name.fromEscapedString.
     * @param value The string to convert to UTF8.
     */
    public 
    Component(String value)
    {
      value_ = new Blob(value.getBytes());
    }
    
    /**
     * Get the component value.
     * @return The component value.
     */
    public final Blob 
    getValue() { return value_; }
    
    /**
     * Write this component value to result, escaping characters according to the 
     * NDN URI Scheme. This also adds "..." to a value with zero or more ".".
     * @param result The StringBuilder to write to.
     */
    public final void 
    toEscapedString(StringBuilder result)
    {
      Name.toEscapedString(value_.buf(), result);
    }
    
    /**
     * Convert this component value by escaping characters according to the 
     * NDN URI Scheme. This also adds "..." to a value with zero or more ".".
     * @return The escaped string.
     */
    public final String
    toEscapedString()
    {
      return Name.toEscapedString(value_.buf());
    }
    
    /**
     * Interpret this name component as a network-ordered number and return an integer.
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
     * Interpret this name component as a network-ordered number with a marker and return an integer.
     * @param marker The required first byte of the component.
     * @return The integer number.
     * @throws EncodingException If the first byte of the component does not equal the marker.
     */
    public final long
    toNumberWithMarker(byte marker) throws EncodingException
    {
      ByteBuffer buffer = value_.buf();
      if (buffer == null || buffer.remaining() <= 0 || buffer.get(0) != marker)
        throw new EncodingException("Name component does not begin with the expected marker.");

      long result = 0;
      for (int i = buffer.position() + 1; i < buffer.limit(); ++i) {
        result *= 256;
        result += (long)((int)buffer.get(i) & 0xff);
      }

      return result;
    }
    
    /**
     * Interpret this name component as a segment number according to NDN name conventions (a network-ordered number 
     * where the first byte is the marker 0x00).
     * @return The integer segment number.
     * @throws EncodingException If the first byte of the component is not the expected marker.
     */
    public final long
    toSegment() throws EncodingException
    {
      return toNumberWithMarker((byte)0x00);
    }
    
    /**
     * Interpret this name component as a version number according to NDN name conventions (a network-ordered number 
     * where the first byte is the marker 0xFD).  Note that this returns the exact number from the component
     * without converting it to a time representation.
     * @return The integer segment number.
     * @throws EncodingException If the first byte of the component is not the expected marker.
     */
    public final long
    toVersion() throws EncodingException
    {
      return toNumberWithMarker((byte)0xFD);
    }
    
    /**
     * Create a component whose value is the network-ordered encoding of the number.
     * Note: if the number is zero or negative, the result is empty.
     * @param number The number to be encoded.
     * @return The component value.
     */ 
    public static Component
    fromNumber(long number)
    {
      if (number < 0)
        number = 0;
      
      // First encode in little endian.
      ByteBuffer buffer = ByteBuffer.allocate(8);
      while (number != 0) {
        buffer.put((byte)(number & 0xff));
        number >>= 8;
      }

      // Make it big endian.
      buffer.flip();
      reverse(buffer, buffer.position(), buffer.limit());
      
      return new Component(new Blob(buffer, false));
    }
        
    /**
     * Create a component whose value is the marker appended with the network-ordered encoding of the number.
     * Note: if the number is zero or negative, no bytes are used for the number - the result will have only the marker.
     * @param number The number to be encoded.
     * @param marker The marker to use as the first byte of the component.
     * @return The component value.
     */
    public static Component
    fromNumberWithMarker(long number, byte marker)
    {
      if (number < 0)
        number = 0;
      
      ByteBuffer buffer = ByteBuffer.allocate(9);
      buffer.put(marker);

      // First encode in little endian.
      while (number != 0) {
        buffer.put((byte)(number & 0xff));
        number >>= 8;
      }

      // Make it big endian.
      buffer.flip();
      reverse(buffer, buffer.position() + 1, buffer.limit());
      
      return new Component(new Blob(buffer, false));
    }
    
    /**
     * Reverse the bytes in buffer starting at position, up to but not including limit.
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
  Name(ArrayList<Component> components)
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
   * Parse the uri according to the NDN URI Scheme and create the name with the components.
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
   * @param i The index of the component, starting from 0.
   * @return The name component at the index.
   */
  public final Component 
  get(int i) { return components_.get(i); }
  
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
    while (iComponentStart < uri.length()) {
      int iComponentEnd = uri.indexOf("/", iComponentStart);
      if (iComponentEnd < 0)
        iComponentEnd = uri.length();

      Component component = new Component(fromEscapedString(uri, iComponentStart, iComponentEnd));
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
   * Append a new component, copying from value.
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public final Name 
  append(byte[] value)
  {
    return append(new Component(value));
  }
  
  /**
   * Append a new component, using the existing Blob value.
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
      append(name.components_.get(i));
  
    return this;
  }

  /**
   * Convert the value to UTF8 bytes and append a Name.Component.
   * Note, this does not escape %XX values.  If you need to escape, use
   * Name.fromEscapedString.  Also, if the string has "/", this does not split
   * into separate components.  If you need that then use append(new Name(value)).
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
   * @param iStartComponent The index if the first component to get.
   * @param nComponents The number of components starting at iStartComponent.
   * @return A new name.
   */
  public final Name
  getSubName(int iStartComponent, int nComponents)
  {
    Name result = new Name();

    int iEnd = iStartComponent + nComponents;
    for (int i = iStartComponent; i < iEnd && i < components_.size(); ++i)
      result.components_.add(components_.get(i));

    return result;
  }
  
  /**
   * Get a new name, constructed as a subset of components starting at iStartComponent until the end of the name.
   * @param iStartComponent The index if the first component to get.
   * @return A new name. 
   */
  public final Name
  getSubName(int iStartComponent)
  {
    Name result = new Name();

    for (int i = iStartComponent; i < components_.size(); ++i)
      result.components_.add(components_.get(i));

    return result;
  }
  
  /**
   * Return a new Name with the first nComponents components of this Name.
   * @param nComponents The number of prefix components.  If nComponents is -N then return the prefix up
   * to name.size() - N. For example getPrefix(-1) returns the name without the final component.
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
   * @return The URI string.
   */
  public final String 
  toUri()
  {
    if (components_.isEmpty())
      return "/";

    StringBuilder result = new StringBuilder();
    for (int i = 0; i < components_.size(); ++i) {
      result.append("/");
      toEscapedString(components_.get(i).getValue().buf(), result);
    }

    return result.toString();
  }
  
  /**
   * Append a component with the encoded segment number.
   * @param segment The segment number.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendSegment(long segment)
  {
    return append(Component.fromNumberWithMarker(segment, (byte)0x00));
  }
  
  /**
   * Append a component with the encoded version number.
   * Note that this encodes the exact value of version without converting from a time representation.
   * @param version The version number.
   * @return This name so that you can chain calls to append.
   */
  public final Name
  appendVersion(long version)
  {
    return append(Component.fromNumberWithMarker(version, (byte)0xFD));
  }
  
  /**
   * Check if this name has the same component count and components as the given name.
   * @param object The Name to check.
   * @return true if the object is a Name and the names are equal, otherwise false.
   */
  public boolean 
  equals(Object object)
  {
    if (!(object instanceof Name))
      return false;
    
    Name name = (Name)object;
    if (components_.size() != name.components_.size())
      return false;

    for (int i = 0; i < components_.size(); ++i) {
      if (!components_.get(i).getValue().buf().equals(name.components_.get(i).getValue().buf()))
        return false;
    }

    return true;
  }
  
  /**
   * Check if the N components of this name are the same as the first N components of the given name.
   * @param name The Name to check.
   * @return true if this matches the given name, otherwise false.  This always returns true if this name is empty.
   */
  public final boolean  
  match(Name name)
  {
    // This name is longer than the name we are checking it against.
    if (components_.size() > name.components_.size())
      return false;

    // Check if at least one of given components doesn't match.
    for (int i = 0; i < components_.size(); ++i) {
      if (!components_.get(i).getValue().buf().equals(name.components_.get(i).getValue().buf()))
        return false;
    }

    return true;
  }

  @Override
  public final long getChangeCount() { return changeCount_; }
  
  /**
   * Make a Blob value by decoding the escapedString between beginOffset and 
   * endOffset according to the NDN URI Scheme. If the escaped string is 
   * "", "." or ".." then return a Blob with a null pointer, which means the 
   * component should be skipped in a URI name.
   * @param escapedString The escaped string
   * @param beginOffset The offset in escapedString of the beginning of the portion to decode.
   * @param endOffset The offset in escapedString of the end of the portion to decode.
   * @return The Blob value. If the escapedString is not a valid escaped component, 
   * then the Blob has a null pointer.
   */
  public static Blob
  fromEscapedString(String escapedString, int beginOffset, int endOffset)
  {
    String trimmedString = escapedString.substring(beginOffset, endOffset).trim();
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
   * Make a Blob value by decoding the escapedString according to the NDN URI Scheme.
   * If the escaped string is "", "." or ".." then return a Blob with a null pointer, 
   * which means the component should be skipped in a URI name.
   * @param escapedString The escaped string.
   * @return The Blob value. If the escapedString is not a valid escaped component, 
   * then the Blob has a null pointer.
   */
  public static Blob 
  fromEscapedString(String escapedString)
  {
    return fromEscapedString(escapedString, 0, escapedString.length());
  }

  /**
   * Write the value to result, escaping characters according to the NDN URI Scheme.
   * This also adds "..." to a value with zero or more ".".
   * @param value The ByteBuffer with the value.  This reads from position() to limit().
   * @param result The StringBuilder to write to.
   */
  public static void
  toEscapedString(ByteBuffer value, StringBuilder result)
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
   * @param value The ByteBuffer with the value.  This reads from position() to limit().
   * @return The escaped string.
   */
  public static String
  toEscapedString(ByteBuffer value)
  {
    StringBuilder result = new StringBuilder(value.remaining());
    toEscapedString(value, result);
    return result.toString();
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
}
