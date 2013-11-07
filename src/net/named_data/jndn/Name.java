/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.util.ArrayList;
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
    
    public Blob getValue() { return value_; }
    
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
  public int size() { return components_.size(); }
  
  /**
   * Get the component at the given index.
   * @param i The index of the component, starting from 0.
   * @return The name component at the index.
   */
  public Component get(int i) { return components_.get(i); }
  
  /**
   * Clear all the components.
   */
  public void clear() { components_.clear(); }
  
  /**
   * Append a new component, copying from value.
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public Name append(byte[] value)
  {
    components_.add(new Component(value));
    return this;
  }
  
  /**
   * Append a new component, using the existing Blob value.
   * @param value The component value.
   * @return This name so that you can chain calls to append.
   */
  public Name append(Blob value)
  {
    components_.add(new Component(value));
    return this;
  }
  
  /**
   * Append the component to this name.
   * @param component The component to append.
   * @return This name so that you can chain calls to append.
   */
  public Name append(Component component)
  {
    components_.add(component);
    return this;
  }
  
  public Name append(Name name)
  {
    if (name == this)
      // Copying from this name, so need to make a copy first.
      return append(new Name(name));

    for (int i = 0; i < name.components_.size(); ++i)
      components_.add(name.components_.get(i));
  
    return this;
  }
  
  private final ArrayList<Component> components_;
}
