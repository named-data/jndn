/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package net.named_data.jndn;

/**
 * A KeyNameType specifies the type of a key locator name in a KeyLocator 
 * object.
 */
public enum KeyNameType {
  NONE, PUBLISHER_PUBLIC_KEY_DIGEST, PUBLISHER_CERTIFICATE_DIGEST, 
  PUBLISHER_ISSUER_KEY_DIGEST, PUBLISHER_ISSUER_CERTIFICATE_DIGEST
}
