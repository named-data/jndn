/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.util.ArrayList;

/**
 * An Exclude holds an Array of Exclude.Entry.
 */
public class Exclude {
  public enum Type {
    COMPONENT, ANY
  }
  
  /**
   * An Exclude.Entry holds an Exclude.Type, and if it is a COMPONENT, it holds 
   * the component value.
   */
  public static class Entry {
    /**
     * Create an Exclude.Entry of type ANY
     */
    public Entry()
    {    
      type_ = Type.ANY;
      component_ = null;
    }

    /**
     * Create an Exclude.Entry of type COMPONENT.
     * @param component The component value.
     */
    public Entry(Name.Component component) 
    {
      type_ = Type.COMPONENT;
      component_ = component;
    }

    /**
     * Get the type of this entry.
     * @return The Exclude.Type.
     */
    public final Exclude.Type 
    getType() { return type_; }

    /**
     * Get the component value for this entry (if it is of type COMPONENT).
     * @return The component value, or null if this entry is not of type 
     * COMPONENT.
     */
    public final Name.Component 
    getComponent() { return component_; }

    private final Exclude.Type type_;
    private final Name.Component component_; /**< only used if type_ is 
                                                  ndn_Exclude_COMPONENT */
  }
  
  /**
   * Create a new Exclude with no entries.
   */
  public Exclude() 
  {
    entries_ = new ArrayList<Entry>();
  }
  
  /**
   * Get the number of entries.
   * @return The number of entries.
   */
  public final int 
  size() { return entries_.size(); }
  
  /**
   * Get the entry at the given index.
   * @param i The index of the entry, starting from 0.
   * @return The entry at the index.
   */
  public final Exclude.Entry
  get(int i) { return (Exclude.Entry)entries_.get(i); }
  
  /**
   * Append a new entry of type Exclude.Type.ANY.
   * @return This Exclude so that you can chain calls to append.
   */
  public final Exclude
  appendAny()
  {    
    entries_.add(new Entry());
    return this;
  }
  
  /**
   * Append a new entry of type Exclude.Type.COMPONENT, taking another pointer 
   * to the Name.Component.
   * @param component The component value for the entry.
   * @return This Exclude so that you can chain calls to append.
   */
  public final Exclude
  appendComponent(Name.Component component) 
  {
    entries_.add(new Entry(component));
    return this;
  }
  
  /**
   * Clear all the entries.
   */
  public final void 
  clear() 
  {
    entries_.clear();
  }
  
  /**
   * Encode this Exclude with elements separated by "," and Exclude.Type.ANY 
   * shown as "*".
   * @return the URI string
   */
  public final String 
  toUri()
  {
    if (entries_.isEmpty())
      return "";

    StringBuffer result = new StringBuffer();
    for (int i = 0; i < entries_.size(); ++i) {
      if (i > 0)
        result.append(",");

      if (get(i).getType() == Exclude.Type.ANY)
        result.append("*");
      else
        Name.toEscapedString(get(i).getComponent().getValue().buf(), result);
    }

    return result.toString();      
  }
  
  private final ArrayList entries_;
}
