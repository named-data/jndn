/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.util.ArrayList;
import java.nio.ByteBuffer;
import net.named_data.jndn.util.Blob;

/**
 * A Name holds an array of Name.Component and represents an NDN name.
 */
public class Name {
  /**
   * A Name.Component holds a read-only name component value.
   */
  public class Component {
    /**
     * Create a new Name.Component, using the existing the Blob value.
     * @param value The component value.
     */
    public Component(Blob value)
    {
      value_ = value;
    }
    
    /**
     * Create a new Name.Component, copying the given value.
     * @param value The value byte array.
     */
    public Component(byte[] value)
    {
      value_ = new Blob(value);
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
    
    private final Blob value_;
  }
  
  /**
   * Create a new Name with no components.
   */
  public Name()
  {
    components_ = new ArrayList<>();          
  }
  
  /**
   * Create a new Name with the components in the given name.
   * @param name The name with components to copy from.
   */
  public Name(Name name)
  {
    components_ = new ArrayList<>(name.components_);
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
  
  /**
   * Clear all the components.
   */
  public final void 
  clear() { components_.clear(); }
  
  /**
   * Append a new component, copying from value.
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public final Name 
  append(byte[] value)
  {
    components_.add(new Component(value));
    return this;
  }
  
  /**
   * Append a new component, using the existing Blob value.
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public final Name 
  append(Blob value)
  {
    components_.add(new Component(value));
    return this;
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
    return this;
  }
  
  public final Name 
  append(Name name)
  {
    if (name == this)
      // Copying from this name, so need to make a copy first.
      return append(new Name(name));

    for (int i = 0; i < name.components_.size(); ++i)
      components_.add(name.components_.get(i));
  
    return this;
  }
  
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
    String value = unescape(trimmedString);

    // Check for all dots.
    boolean gotNonDot = false;
    for (int i = 0; i < value.length(); ++i) {
      if (value.charAt(i) != '.') {
        gotNonDot = true;
        break;
      }
    }
    
    if (!gotNonDot) {
      // Special case for component of only periods.  
      if (value.length() <= 2)
        // Zero, one or two periods is illegal.  Ignore this component.
        return new Blob();
      else
        // Remove 3 periods.
        return new Blob(value.substring(3).getBytes());
    }
    else
      return new Blob(value.getBytes());
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
   * @return The unescaped string.
   */
  private static String 
  unescape(String str)
  {
    StringBuilder result = new StringBuilder(str.length());

    for (int i = 0; i < str.length(); ++i) {
      if (str.charAt(i) == '%' && i + 2 < str.length()) {
        int hi = fromHexChar(str.charAt(i + 1));
        int lo = fromHexChar(str.charAt(i + 2));

        if (hi < 0 || lo < 0)
          // Invalid hex characters, so just keep the escaped string.
          result.append(str.charAt(i)).append(str.charAt(i + 1)).append(str.charAt(i + 2));
        else
          result.append((char)(16 * hi + lo));

        // Skip ahead past the escaped value.
        i += 2;
      }
      else
        // Just copy through.
        result.append(str.charAt(i));
    }

    return result.toString();
  }
  
  public static void main(String[] args) 
  {
    System.out.println(Name.toEscapedString(Name.)
  }

  private final ArrayList<Component> components_;
}
