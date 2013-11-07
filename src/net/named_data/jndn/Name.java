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
    public Blob getValue() { return value_; }
    
    private Blob value_;
  }
  
  public Name()
  {
    components_ = new ArrayList<>();          
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
  
  private final ArrayList<Component> components_;
}
