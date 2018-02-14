/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/trust-anchor-container.cpp
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

package net.named_data.jndn.security.v2;

import java.util.HashMap;
import java.util.TreeMap;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Common;

/**
 * A TrustAnchorContainer represents a container for trust anchors.
 *
 * There are two kinds of anchors:
 * static anchors that are permanent for the lifetime of the container, and
 * dynamic anchors that are periodically updated.
 *
 * Trust anchors are organized in groups. Each group has a unique group id.
 * The same anchor certificate (same name without considering the implicit
 * digest) can be inserted into multiple groups, but no more than once into each.
 *
 * Dynamic groups are created using the appropriate TrustAnchorContainer.insert
 * method. Once created, the dynamic anchor group cannot be updated.
 *
 * The returned pointer to Certificate from `find` methods is only guaranteed to
 * be valid until the next invocation of `find` and may be invalidated
 * afterwards.
 */
public class TrustAnchorContainer {
  /**
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Insert a static trust anchor. If the certificate (having the same name
   * without considering implicit digest) already exists in the group with
   * groupId, then do nothing.
   * @param groupId The certificate group id.
   * @param certificate The certificate to insert, which is copied.
   * @throws TrustAnchorContainer.Error If groupId is a dynamic anchor group .
   */
  public final void
  insert(String groupId, CertificateV2 certificate)
    throws TrustAnchorContainer.Error
  {
    TrustAnchorGroup group = groups_.get(groupId);
    if (group == null) {
      group = new StaticTrustAnchorGroup(anchors_, groupId);
      groups_.put(groupId, group);
    }

    if (!(group instanceof StaticTrustAnchorGroup))
      throw new TrustAnchorContainer.Error
        ("Cannot add a static anchor to the non-static anchor group " + groupId);

    ((StaticTrustAnchorGroup)group).add(certificate);
  }

  /**
   * Insert dynamic trust anchors from the path.
   * @param groupId The certificate group id, which must not be empty.
   * @param path The path to load the trust anchors.
   * @param refreshPeriod  The refresh time in milliseconds for the anchors
   * under path. This must be positive. The relevant trust anchors will only be
   * updated when find is called.
   * @param isDirectory If true, then path is a directory. If false, it is a
   * single file.
   * @throws IllegalArgumentException If refreshPeriod is not positive.
   * @throws TrustAnchorContainer.Error a group with groupId already exists
   */
  public final void
  insert
    (String groupId, String path, double refreshPeriod, boolean isDirectory)
    throws TrustAnchorContainer.Error
  {
    if (groups_.containsKey(groupId))
      throw new TrustAnchorContainer.Error
        ("Cannot create the dynamic group, because group " + groupId +
        " already exists");

    groups_.put(groupId, new DynamicTrustAnchorGroup
      (anchors_, groupId, path, refreshPeriod, isDirectory));
  }

  /**
   * Call the main insert where isDirectory is false.
   */
  public final void
  insert(String groupId, String path, double refreshPeriod)
    throws TrustAnchorContainer.Error
  {
    insert(groupId, path, refreshPeriod, false);
  }

  /**
   * Remove all static and dynamic anchors.
   */
  public final void
  clear()
  {
    groups_.clear();
    anchors_.clear();
  }

  /**
   * Search for a certificate across all groups (longest prefix match).
   * @param keyName The key name prefix for searching for the certificate.
   * @return The found certificate, or null if not found.
   */
  public final CertificateV2
  find(Name keyName)
  {
    refresh();

    Name nameKey = (Name)anchors_.anchorsByName_.ceilingKey(keyName);
    if (nameKey == null)
      return null;
    CertificateV2 certificate =
      (CertificateV2)anchors_.anchorsByName_.get(nameKey);
    if (!keyName.isPrefixOf(certificate.getName()))
      return null;
    return certificate;
  }

  /**
   * Find a certificate for the given interest.
   * @param interest The input interest packet.
   * @return The found certificate, or null if not found.
   * @note Interest with implicit digest is not supported.
   * @note ChildSelector is not supported.
   */
  public final CertificateV2
  find(Interest interest)
  {
    refresh();

    Name firstKey = (Name)anchors_.anchorsByName_.ceilingKey(interest.getName());
    if (firstKey == null)
      return null;

    for (Object key : anchors_.anchorsByName_.navigableKeySet().tailSet(firstKey)) {
      CertificateV2 certificate = (CertificateV2)anchors_.anchorsByName_.get
        ((Name)key);
      if (!interest.getName().isPrefixOf(certificate.getName()))
        break;

      try {
        if (interest.matchesData(certificate))
          return certificate;
      } catch (EncodingException ex) {
        // We don't expect this to happen.
        throw new java.lang.Error("Error in matchesData: " + ex);
      }
    }

    return null;
  }

  /**
   * Get the trust anchor group for the groupId.
   * @param groupId The group ID.
   * @return The trust anchor group.
   * @throws TrustAnchorContainer.Error if the groupId does not exist.
   */
  public final TrustAnchorGroup
  getGroup(String groupId) throws TrustAnchorContainer.Error
  {
    TrustAnchorGroup group = groups_.get(groupId);
    if (group == null)
      throw new TrustAnchorContainer.Error
        ("Trust anchor group " + groupId + " does not exist");

    return group;
  }

  /**
   * Get the number of trust anchors across all groups.
   * @return The number of trust anchors.
   */
  public final int
  size() { return anchors_.size(); }

  private static class AnchorContainer extends CertificateContainerInterface {
    /**
     * Add the certificate to the container.
     * @param certificate The certificate to add, which is copied.
     */
    public void
    add(CertificateV2 certificate)
    {
      CertificateV2 certificateCopy;
      try {
        certificateCopy = new CertificateV2(certificate);
      } catch (CertificateV2.Error ex) {
        // We don't expect this from the copy constructor.
        throw new java.lang.Error
          ("Error in CertificateV2 copy constructor: " + ex);
      }
      anchorsByName_.put(certificateCopy.getName(), certificateCopy);
    }

    /**
     * Remove the certificate with the given name. If the name does not exist,
     * do nothing.
     * @param certificateName The name of the certificate.
     */
    public void
    remove(Name certificateName)
    {
      anchorsByName_.remove(certificateName);
    }

    /**
     * Clear all certificates.
     */
    void
    clear() { anchorsByName_.clear(); }

    /**
     * Get the number of certificates in the container.
     * @return The number of certificates.
     */
    int
    size() { return anchorsByName_.size(); }

    public final TreeMap anchorsByName_ = new TreeMap();
  };

  private void
  refresh()
  {
    for (TrustAnchorGroup group : groups_.values())
      group.refresh();
  }

  private final HashMap<String, TrustAnchorGroup> groups_ =
    new HashMap<String, TrustAnchorGroup>();
  private final AnchorContainer anchors_ = new AnchorContainer();
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
