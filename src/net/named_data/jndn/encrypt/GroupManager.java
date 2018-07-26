/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/group-manager https://github.com/named-data/ndn-group-encrypt
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

package net.named_data.jndn.encrypt;

import net.named_data.jndn.encrypt.algo.Encryptor;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.util.Blob;

/**
 * A GroupManager manages keys and schedules for group members in a particular
 * namespace.
 * @note This class is an experimental feature. The API may change.
 */
public class GroupManager {
  /**
   * Create a group manager with the given values. The group manager namespace
   * is /{prefix}/read/{dataType} .
   * @param prefix The prefix for the group manager namespace.
   * @param dataType The data type for the group manager namespace.
   * @param database The GroupManagerDb for storing the group management
   * information (including user public keys and schedules).
   * @param keySize The group key will be an RSA key with keySize bits.
   * @param freshnessHours The number of hours of the freshness period of data
   *   packets carrying the keys.
   * @param keyChain The KeyChain to use for signing data packets. This signs
   * with the default identity.
   */
  public GroupManager
    (Name prefix, Name dataType, GroupManagerDb database, int keySize,
     int freshnessHours, KeyChain keyChain) throws SecurityException
  {
    namespace_ = new Name(prefix).append(Encryptor.NAME_COMPONENT_READ)
      .append(dataType);
    database_ = database;
    keySize_ = keySize;
    freshnessHours_ = freshnessHours;

    keyChain_ = keyChain;
  }

  /**
   * Create a group key for the interval into which timeSlot falls. This creates
   * a group key if it doesn't exist, and encrypts the key using the public key
   * of each eligible member.
   * @param timeSlot The time slot to cover as milliseconds since Jan 1, 1970 UTC.
   * @param needRegenerate needRegenerate should be true if this is the first
   * time this method is called, or a member was removed. needRegenerate can be
   * false if this is not the first time this method is called, or a member was
   * added.
   * @return A List of Data packets where the first is the E-KEY data packet
   * with the group's public key and the rest are the D-KEY data packets with
   * the group's private key encrypted with the public key of each eligible
   * member. (Use List without generics so it works with older Java compilers.)
   * @throws GroupManagerDb.Error for a database error.
   * @throws SecurityException for an error using the security KeyChain.
   */
  public final List
  getGroupKey(double timeSlot, boolean needRegenerate)
    throws GroupManagerDb.Error, SecurityException, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    Map memberKeys = new TreeMap();
    List result = new ArrayList();

    // Get the time interval.
    Interval finalInterval = calculateInterval(timeSlot, memberKeys);
    if (finalInterval.isValid() == false)
      return result;

    String startTimeStamp = Schedule.toIsoString(finalInterval.getStartTime());
    String endTimeStamp = Schedule.toIsoString(finalInterval.getEndTime());

    // Generate the private and public keys.
    Blob[] privateKeyBlob = { null };
    Blob[] publicKeyBlob = { null };
    Name eKeyName = new Name(namespace_);
    eKeyName.append(Encryptor.NAME_COMPONENT_E_KEY).append(startTimeStamp)
      .append(endTimeStamp);

    if (!needRegenerate && database_.hasEKey(eKeyName))
      getEKey(eKeyName, publicKeyBlob, privateKeyBlob);
    else {
      generateKeyPair(privateKeyBlob, publicKeyBlob);
      if (database_.hasEKey(eKeyName))
        deleteEKey(eKeyName);
      addEKey(eKeyName, publicKeyBlob[0], privateKeyBlob[0]);
    }

    // Add the first element to the result.
    // The E-KEY (public key) data packet name convention is:
    // /<data_type>/E-KEY/[start-ts]/[end-ts]
    Data data = createEKeyData(startTimeStamp, endTimeStamp, publicKeyBlob[0]);
    result.add(data);

    // Encrypt the private key with the public key from each member's certificate.
    for (Object entryObj : memberKeys.entrySet()) {
      Map.Entry entry = (Map.Entry)entryObj;
      Name keyName = (Name)entry.getKey();
      Blob certificateKey = (Blob)entry.getValue();

      // Generate the name of the packet.
      // The D-KEY (private key) data packet name convention is:
      // /<data_type>/D-KEY/[start-ts]/[end-ts]/[member-name]
      data = createDKeyData
        (startTimeStamp, endTimeStamp, keyName, privateKeyBlob[0], certificateKey);
      result.add(data);
    }

    return result;
  }

  /**
   * Call the main getGroupKey where needRegenerate is default true.
   */
  public final List
  getGroupKey(double timeSlot)
    throws GroupManagerDb.Error, SecurityException, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    return getGroupKey(timeSlot, true);
  }

  /**
   * Add a schedule with the given scheduleName.
   * @param scheduleName The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to add.
   * @throws GroupManagerDb.Error if a schedule with the same name already exists,
   * if the name is empty, or other database error.
   */
  public final void
  addSchedule(String scheduleName, Schedule schedule) throws GroupManagerDb.Error
  {
    database_.addSchedule(scheduleName, schedule);
  }

  /**
   * Delete the schedule with the given scheduleName. Also delete members which
   * use this schedule. If there is no schedule with the name, then do nothing.
   * @param scheduleName The name of the schedule.
   * @throws GroupManagerDb.Error for a database error.
   */
  public final void
  deleteSchedule(String scheduleName) throws GroupManagerDb.Error
  {
    database_.deleteSchedule(scheduleName);
  }

  /**
   * Update the schedule with scheduleName and replace the old object with the
   * given schedule. Otherwise, if no schedule with name exists, a new schedule
   * with name and the given schedule will be added to database.
   * @param scheduleName The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to update or add.
   * @throws GroupManagerDb.Error if the name is empty, or other database error.
   */
  public final void
  updateSchedule(String scheduleName, Schedule schedule)
    throws GroupManagerDb.Error
  {
    database_.updateSchedule(scheduleName, schedule);
  }

  /**
   * Add a new member with the given memberCertificate into a schedule named
   * scheduleName. If cert is an IdentityCertificate made from memberCertificate,
   * then the member's identity name is cert.getPublicKeyName().getPrefix(-1).
   * @param scheduleName The schedule name.
   * @param memberCertificate The member's certificate.
   * @throws GroupManagerDb.Error If there's no schedule named scheduleName, if
   * the member's identity name already exists, or other database error.
   * @throws DerDecodingException for error decoding memberCertificate as a
   * certificate.
   */
  public final void
  addMember(String scheduleName, Data memberCertificate)
    throws GroupManagerDb.Error, DerDecodingException
  {
    IdentityCertificate cert = new IdentityCertificate(memberCertificate);
    database_.addMember
      (scheduleName, cert.getPublicKeyName(), cert.getPublicKeyInfo().getKeyDer());
  }

  /**
   * Remove a member with the given identity name. If there is no member with
   * the identity name, then do nothing.
   * @param identity The member's identity name.
   * @throws GroupManagerDb.Error for a database error.
   */
  public final void
  removeMember(Name identity) throws GroupManagerDb.Error
  {
    database_.deleteMember(identity);
  }

  /**
   * Change the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @param scheduleName The new schedule name.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or there's no schedule named scheduleName.
   */
  public final void
  updateMemberSchedule(Name identity, String scheduleName)
    throws GroupManagerDb.Error
  {
    database_.updateMemberSchedule(identity, scheduleName);
  }

  /**
   * Delete all the EKeys in the database.
   * The database will keep growing because EKeys will keep being added, so this
   * method should be called periodically.
   * @throws GroupManagerDb.Error for a database error.
   */
  public void
  cleanEKeys() throws GroupManagerDb.Error { database_.cleanEKeys(); }

  /**
   * Calculate an Interval that covers the timeSlot.
   * @param timeSlot The time slot to cover as milliseconds since Jan 1, 1970 UTC.
   * @param memberKeys First clear memberKeys then fill it with the info of
   * members who are allowed to access the interval. The map's key is the Name
   * of the public key and the value is the Blob of the public key DER. (Use Map
   * without generics so it works with older Java compilers.)
   * @return The Interval covering the time slot.
   * @throws GroupManagerDb.Error for a database error.
   */
  private Interval
  calculateInterval(double timeSlot, Map memberKeys) throws GroupManagerDb.Error
  {
    // Prepare.
    Interval positiveResult = new Interval();
    Interval negativeResult = new Interval();
    memberKeys.clear();

    // Get the all intervals from the schedules.
    List scheduleNames = database_.listAllScheduleNames();
    for (int i = 0; i < scheduleNames.size(); ++i) {
      String scheduleName = (String)scheduleNames.get(i);

      Schedule schedule = database_.getSchedule(scheduleName);
      Schedule.Result result = schedule.getCoveringInterval(timeSlot);
      Interval tempInterval = result.interval;

      if (result.isPositive) {
        if (!positiveResult.isValid())
          positiveResult = tempInterval;
        positiveResult.intersectWith(tempInterval);

        Map map = database_.getScheduleMembers(scheduleName);
        memberKeys.putAll(map);
      }
      else {
        if (!negativeResult.isValid())
          negativeResult = tempInterval;
        negativeResult.intersectWith(tempInterval);
      }
    }
    if (!positiveResult.isValid())
      // Return an invalid interval when there is no member which has an
      // interval covering the time slot.
      return new Interval(false);

    // Get the final interval result.
    Interval finalInterval;
    if (negativeResult.isValid())
      finalInterval = positiveResult.intersectWith(negativeResult);
    else
      finalInterval = positiveResult;

    return finalInterval;
  }

  /**
   * Generate an RSA key pair according to keySize_.
   * @param privateKeyBlob Set privateKeyBlob[0] to the encoding Blob of the
   * private key.
   * @param publicKeyBlob Set publicKeyBlob[0] to the encoding Blob of the
   * public key.
   */
  private void
  generateKeyPair(Blob[] privateKeyBlob, Blob[] publicKeyBlob)
    throws SecurityException
  {
    RsaKeyParams params = new RsaKeyParams(keySize_);

    DecryptKey privateKey = RsaAlgorithm.generateKey(params);

    privateKeyBlob[0] = privateKey.getKeyBits();

    EncryptKey publicKey = RsaAlgorithm.deriveEncryptKey(privateKeyBlob[0]);
    publicKeyBlob[0] = publicKey.getKeyBits();
  }

  /**
   * Create an E-KEY Data packet for the given public key.
   * @param startTimeStamp The start time stamp string to put in the name.
   * @param endTimeStamp The end time stamp string to put in the name.
   * @param publicKeyBlob A Blob of the public key DER.
   * @return The Data packet.
   * @throws SecurityException for an error using the security KeyChain.
   */
  private Data
  createEKeyData(String startTimeStamp, String endTimeStamp, Blob publicKeyBlob)
    throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    Name name = new Name(namespace_);
    name.append(Encryptor.NAME_COMPONENT_E_KEY).append(startTimeStamp)
      .append(endTimeStamp);

    Data data = new Data(name);
    data.getMetaInfo().setFreshnessPeriod(freshnessHours_ * MILLISECONDS_IN_HOUR);
    data.setContent(publicKeyBlob);
    keyChain_.sign(data);
    return data;
  }

  /**
   * Create a D-KEY Data packet with an EncryptedContent for the given private
   * key, encrypted with the certificate key.
   * @param startTimeStamp The start time stamp string to put in the name.
   * @param endTimeStamp The end time stamp string to put in the name.
   * @param keyName The key name to put in the data packet name and the
   * EncryptedContent key locator.
   * @param privateKeyBlob A Blob of the encoded private key.
   * @param certificateKey The certificate key encoding, used to encrypt the
   * private key.
   * @return The Data packet.
   * @throws SecurityException for an error using the security KeyChain.
   */
  private Data
  createDKeyData
    (String startTimeStamp, String endTimeStamp, Name keyName,
     Blob privateKeyBlob, Blob certificateKey)
    throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    Name name = new Name(namespace_);
    name.append(Encryptor.NAME_COMPONENT_D_KEY);
    name.append(startTimeStamp).append(endTimeStamp);
    Data data = new Data(name);
    data.getMetaInfo().setFreshnessPeriod(freshnessHours_ * MILLISECONDS_IN_HOUR);
    EncryptParams encryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    try {
      Encryptor.encryptData
        (data, privateKeyBlob, keyName, certificateKey, encryptParams);
    } catch (Exception ex) {
      // Consolidate errors such as InvalidKeyException.
      throw new SecurityException
        ("createDKeyData: Error in encryptData: " + ex.getMessage());
    }

    keyChain_.sign(data);
    return data;
  }

  /**
   * Add the EKey with name eKeyName to the database.
   * @param eKeyName The name of the EKey. This copies the Name.
   * @param publicKey The encoded public Key of the group key pair.
   * @param privateKey The encoded private Key of the group key pair.
   * @throws GroupManagerDb.Error If a key with name eKeyName already exists in
   * the database, or other database error.
   */
  private void
  addEKey(Name eKeyName, Blob publicKey, Blob privateKey) throws GroupManagerDb.Error
  {
    database_.addEKey(eKeyName, publicKey, privateKey);
  }

  /**
   * Get the group key pair with the name eKeyName from the database.
   * @param eKeyName The name of the EKey.
   * @param publicKey Set publicKey[0] to the encoded public Key.
   * @param privateKey Set publicKey[0] to the encoded private Key.
   * @throws GroupManagerDb.Error If the key with name eKeyName does not exist
   * in the database, or other database error.
   */
  private void
  getEKey(Name eKeyName, Blob[] publicKey, Blob[] privateKey)
    throws GroupManagerDb.Error
  {
    database_.getEKey(eKeyName, publicKey, privateKey);
  }

  /**
   * Delete the EKey with name eKeyName from the database. If no key with the
   * name exists in the database, do nothing.
   * @param eKeyName The name of the EKey.
   * @throws GroupManagerDb.Error for a database error.
   */
  private void
  deleteEKey(Name eKeyName) throws GroupManagerDb.Error
  {
    database_.deleteEKey(eKeyName);
  }

  /**
   * A class implements Friend if it has a method setGroupManagerFriendAccess
   * which setFriendAccess calls to set the FriendAccess object.
   */
  public interface Friend {
    void setGroupManagerFriendAccess(FriendAccess friendAccess);
  }

  /**
   * Call friend.setGroupManagerFriendAccess to pass an instance of
   * a FriendAccess class to allow a friend class to call private methods.
   * @param friend The friend class for calling setGroupManagerFriendAccess.
   * This uses friend.getClass() to make sure that it is a friend class.
   * Therefore, only a friend class gets an implementation of FriendAccess.
   */
  public static void setFriendAccess(Friend friend)
  {
    if (friend.getClass().getName().endsWith
          ("net.named_data.jndn.tests.integration_tests.TestGroupManager"))
    {
      friend.setGroupManagerFriendAccess(new FriendAccessImpl());
    }
  }

  /**
   * A friend class can call the methods of FriendAccess to access private
   * methods.  This abstract class is public, but setFriendAccess passes an
   * instance of a private class which implements the methods.
   */
  public abstract static class FriendAccess {
    public abstract Interval
    calculateInterval
      (GroupManager groupManager, double timeSlot, Map memberKeys)
      throws GroupManagerDb.Error;

    public abstract Data
    createDKeyData
      (GroupManager groupManager, String startTimeStamp, String endTimeStamp,
       Name keyName, Blob privateKeyBlob, Blob certificateKey)
      throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error;

    public abstract Data
      createEKeyData
        (GroupManager groupManager, String startTimeStamp, String endTimeStamp,
         Blob publicKeyBlob)
        throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error;
  }

  /**
   * setFriendAccess passes an instance of this private class which implements
   * the FriendAccess methods.
   */
  private static class FriendAccessImpl extends FriendAccess {
    public Interval
    calculateInterval
      (GroupManager groupManager, double timeSlot, Map memberKeys)
      throws GroupManagerDb.Error
    {
      return groupManager.calculateInterval(timeSlot, memberKeys);
    }

    public Data
    createDKeyData
      (GroupManager groupManager, String startTimeStamp, String endTimeStamp,
       Name keyName, Blob privateKeyBlob, Blob certificateKey)
      throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
    {
      return groupManager.createDKeyData
        (startTimeStamp, endTimeStamp, keyName, privateKeyBlob, certificateKey);
    }

    public Data
      createEKeyData
        (GroupManager groupManager, String startTimeStamp, String endTimeStamp,
         Blob publicKeyBlob)
        throws SecurityException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
    {
      return groupManager.createEKeyData
        (startTimeStamp, endTimeStamp, publicKeyBlob);
    }
  }

  private final Name namespace_;
  private final GroupManagerDb database_;
  private final int keySize_;
  private final int freshnessHours_;
  private final KeyChain keyChain_;

  private static final long MILLISECONDS_IN_HOUR = 3600 * 1000;
}
