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

import java.util.ArrayList;
import net.named_data.jndn.util.ChangeCountable;

/**
 * An Exclude holds an Array of Exclude.Entry.
 */
public class Exclude implements ChangeCountable {
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
                                                  Exclude.Type.COMPONENT */
  }

  /**
   * Create a new Exclude with no entries.
   */
  public Exclude()
  {
    entries_ = new ArrayList<Entry>();
  }

  /**
   * Create a new Exclude as a copy of the given exclude.
   * @param exclude The Exclude to copy.
   */
  public Exclude(Exclude exclude)
  {
    // Each entry is read-only, so do a shallow copy.
    entries_ = new ArrayList<Entry>(exclude.entries_);
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
  get(int i) { return entries_.get(i); }

  /**
   * Append a new entry of type Exclude.Type.ANY.
   * @return This Exclude so that you can chain calls to append.
   */
  public final Exclude
  appendAny()
  {
    entries_.add(new Entry());
    ++changeCount_;
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
    ++changeCount_;
    return this;
  }

  /**
   * Clear all the entries.
   */
  public final void
  clear()
  {
    entries_.clear();
    ++changeCount_;
  }

  /**
   * Check if the component matches any of the exclude criteria.
   * @param component The name component to check.
   * @return True if the component matches any of the exclude criteria,
   * otherwise false.
   */
  public boolean
  matches(Name.Component component)
  {
    for (int i = 0; i < entries_.size(); ++i) {
      if (get(i).getType() == Exclude.Type.ANY) {
        Entry lowerBound = null;
        if (i > 0)
          lowerBound = get(i - 1);

        // Find the upper bound, possibly skipping over multiple ANY in a row.
        int iUpperBound;
        Entry upperBound = null;
        for (iUpperBound = i + 1; iUpperBound < entries_.size(); ++iUpperBound) {
          if (get(iUpperBound).getType() == Exclude.Type.COMPONENT) {
            upperBound = get(iUpperBound);
            break;
          }
        }

        // If lowerBound != null, we already checked component equals lowerBound on the last pass.
        // If upperBound != null, we will check component equals upperBound on the next pass.
        if (upperBound != null) {
          if (lowerBound != null) {
            if (component.compare(lowerBound.getComponent()) > 0 &&
                component.compare(upperBound.getComponent()) < 0)
              return true;
          }
          else {
            if (component.compare(upperBound.getComponent()) < 0)
              return true;
          }

          // Make i equal iUpperBound on the next pass.
          i = iUpperBound - 1;
        }
        else {
          if (lowerBound != null) {
            if (component.compare(lowerBound.getComponent()) > 0)
              return true;
          }
          else
            // entries_ has only ANY.
            return true;
        }
      }
      else {
        if (component.equals(get(i).getComponent()))
          return true;
      }
    }

    return false;
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
        get(i).getComponent().toEscapedString(result);
    }

    return result.toString();
  }

  /**
   * Get the change count, which is incremented each time this object is
   * changed.
   * @return The change count.
   */
  public final long
  getChangeCount() { return changeCount_; }

  private final ArrayList<Entry> entries_;
  private long changeCount_ = 0;
}
