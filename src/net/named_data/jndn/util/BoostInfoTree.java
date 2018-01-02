/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN boost_info_parser by Adeola Bannis.
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

package net.named_data.jndn.util;

import java.util.ArrayList;

/**
 * BoostInfoTree is provided for compatibility with the Boost INFO property list
 * format used in ndn-cxx.
 *
 * Each node in the tree may have a name and a value as well as associated
 * sub-trees. The sub-tree names are not unique, and so sub-trees are stored as
 * dictionaries where the key is a sub-tree name and the values are the
 * sub-trees sharing the same name.
 *
 * Nodes can be accessed with a path syntax, as long as nodes in the path do not
 * contain the path separator '/' in their names.
 */
public class BoostInfoTree {
  public BoostInfoTree(String value, BoostInfoTree parent)
  {
    value_ = value;
    parent_ = parent;
  }

  public BoostInfoTree(String value)
  {
    value_ = value;
  }

  public BoostInfoTree()
  {
  }

  /**
   * Insert a BoostInfoTree as a sub-tree with the given name.
   * @param treeName The name of the new sub-tree.
   * @param newTree The sub-tree to add.
   */
  public final void
  addSubtree(String treeName, BoostInfoTree newTree)
  {
    ArrayList<BoostInfoTree> subtreeList = find(treeName);
    if (subtreeList != null)
      subtreeList.add(newTree);
    else {
      TreeEntry entry = new TreeEntry(treeName);
      subtrees_.add(entry);
      entry.subtreeList_.add(newTree);
    }

    newTree.parent_ = this;
    lastChild_ = newTree;
  }

  /**
   * Create a new BoostInfoTree and insert it as a sub-tree with the given name.
   * @param treeName The name of the new sub-tree.
   * @param value The value associated with the new sub-tree.
   * @return The created sub-tree.
   */
  public final BoostInfoTree
  createSubtree(String treeName, String value)
  {
    BoostInfoTree newTree = new BoostInfoTree(value, this);
    addSubtree(treeName, newTree);
    return newTree;
  }

  /**
   * Create a new BoostInfoTree with where the value is an empty string,
   * and insert it as a sub-tree with the given name.
   * @param treeName The name of the new sub-tree.
   * @return The created sub-tree.
   */
  public final BoostInfoTree
  createSubtree(String treeName)
  {
    return createSubtree(treeName, "");
  }

  /**
   * Look up using the key and return a list of the subtrees.
   * @param key The key which may be a path separated with '/'.
   * @return A new ArrayList of BoostInfoTree which are the subtrees.
   */
  public final ArrayList<BoostInfoTree>
  get(String key)
  {
    ArrayList<BoostInfoTree> foundVals = new ArrayList<BoostInfoTree>();

    // Strip beginning '/'.
    key = key.replaceFirst("^/+", "");
    if (key.length() == 0) {
      foundVals.add(this);
      return foundVals;
    }
    String[] path = key.split("/");

    ArrayList<BoostInfoTree> subtrees = find(path[0]);
    if (subtrees == null)
      return foundVals;
    if (path.length == 1)
      return (ArrayList<BoostInfoTree>)subtrees.clone();

    // newPath = path.slice(1).join('/')
    // Implement manually because older Java versions don't have join.
    String newPath = "";
    for (int i = 1; i < path.length; ++i) {
      if (i > 1)
        newPath += "/";
      newPath += path[i];
    }

    for (int i = 0; i < subtrees.size(); ++i) {
      BoostInfoTree t = subtrees.get(i);
      ArrayList<BoostInfoTree> partial = t.get(newPath);
      foundVals.addAll(partial);
    }

    return foundVals;
  }

  /**
   * Look up using the key and return string value of the first subtree.
   * @param key The key which may be a path separated with '/'.
   * @return A pointer to the string value or null if not found.
   */
  public final String
  getFirstValue(String key)
  {
    ArrayList<BoostInfoTree> list = get(key);
    if (list.size() >= 1)
      return list.get(0).value_;
    else
      return null;
  }

  public final String
  getValue() { return value_; }

  public final BoostInfoTree
  getParent() { return parent_; }

  public final BoostInfoTree
  getLastChild() { return lastChild_; }

  public final String
  prettyPrint(int indentLevel)
  {
    // Set prefix to indentLevel spaces.
    String prefix = new String(new char[indentLevel]).replace("\0", " ");
    String s = "";

    if (parent_ != null) {
      if (value_.length() > 0)
        s += "\"" + value_ + "\"";
      s += "\n";
    }

    if (subtrees_.size() > 0) {
      if (parent_ != null)
        s += prefix+ "{\n";
      String nextLevel = new String(new char[indentLevel + 2]).replace("\0", " ");
      for (int i = 0; i < subtrees_.size(); ++i) {
        TreeEntry entry = subtrees_.get(i);
        for (int iSubTree = 0; iSubTree < entry.subtreeList_.size(); ++iSubTree)
          s += nextLevel + entry.treeName_ + " " +
            (entry.subtreeList_.get(iSubTree)).prettyPrint(indentLevel + 2);
      }

      if (parent_ != null)
        s +=  prefix + "}\n";
    }

    return s;
  }

  public final String
  prettyPrint()
  {
    return prettyPrint(1);
  }

  public String
  toString() { return prettyPrint(); }

  private class TreeEntry {
    public TreeEntry(String treeName)
    {
      treeName_ = treeName;
    }

    public String treeName_;
    public ArrayList<BoostInfoTree> subtreeList_ = new ArrayList<BoostInfoTree>();
  }

  /**
   * Use treeName to find the vector of BoostInfoTree in subtrees_.
   * @param value The key in subtrees_ to search for.  This does a flat search
   * in subtrees_.  It does not split by '/' into a path.
   * @return A list of BoostInfoTree, or null if not found.
   */
  private ArrayList<BoostInfoTree>
  find(String treeName)
  {
    for (int i = 0; i < subtrees_.size(); ++i) {
      TreeEntry entry = subtrees_.get(i);
      if (entry.treeName_.equals(treeName))
        return entry.subtreeList_;
    }

    return null;
  }

  // We can't use a map for subtrees_ because we want the keys to be in order.
  private ArrayList<TreeEntry> subtrees_ = new ArrayList<TreeEntry>();
  private String value_ = "";
  private BoostInfoTree parent_ = null;
  private BoostInfoTree lastChild_ = null;
}
