/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/transform/private-key.t.cpp
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

package net.named_data.jndn.tests.unit_tests;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.EcKeyParams;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.VerificationHelpers;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.security.tpm.TpmPrivateKey;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestTpmPrivateKey {
  class KeyTestData {
    public KeyParams keyParams;
    public String privateKeyPkcs1;
    public String privateKeyPkcs8;
    public String privateKeyPkcs8Unencrypted;
    public String publicKeyEncoding;
  }

  class RsaKeyTestData extends KeyTestData {
    public RsaKeyTestData()
    {
      keyParams = new RsaKeyParams();

      privateKeyPkcs1 =
"MIIEpAIBAAKCAQEAw0WM1/WhAxyLtEqsiAJgWDZWuzkYpeYVdeeZcqRZzzfRgBQT\n" +
"sNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobws3iigohnM9yTK+KKiayPhIAm/+5H\n" +
"GT6SgFJhYhqo1/upWdueojil6RP4/AgavHhopxlAVbk6G9VdVnlQcQ5Zv0OcGi73\n" +
"c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9gZwIL5PuE9BiO6I39cL9z7EK1SfZh\n" +
"OWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA9rH58ynaAix0tcR/nBMRLUX+e3rU\n" +
"RHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0ywIDAQABAoIBADQkckOIl4IZMUTn\n" +
"W8LFv6xOdkJwMKC8G6bsPRFbyY+HvC2TLt7epSvfS+f4AcYWaOPcDu2E49vt2sNr\n" +
"cASly8hgwiRRAB3dHH9vcsboiTo8bi2RFvMqvjv9w3tK2yMxVDtmZamzrrnaV3YV\n" +
"Q+5nyKo2F/PMDjQ4eUAKDOzjhBuKHsZBTFnA1MFNI+UKj5X4Yp64DFmKlxTX/U2b\n" +
"wzVywo5hzx2Uhw51jmoLls4YUvMJXD0wW5ZtYRuPogXvXb/of9ef/20/wU11WFKg\n" +
"Xb4gfR8zUXaXS1sXcnVm3+24vIs9dApUwykuoyjOqxWqcHRec2QT2FxVGkFEraze\n" +
"CPa4rMECgYEA5Y8CywomIcTgerFGFCeMHJr8nQGqY2V/owFb3k9maczPnC9p4a9R\n" +
"c5szLxA9FMYFxurQZMBWSEG2JS1HR2mnjigx8UKjYML/A+rvvjZOMe4M6Sy2ggh4\n" +
"SkLZKpWTzjTe07ByM/j5v/SjNZhWAG7sw4/LmPGRQkwJv+KZhGojuOkCgYEA2cOF\n" +
"T6cJRv6kvzTz9S0COZOVm+euJh/BXp7oAsAmbNfOpckPMzqHXy8/wpdKl6AAcB57\n" +
"OuztlNfV1D7qvbz7JuRlYwQ0cEfBgbZPcz1p18HHDXhwn57ZPb8G33Yh9Omg0HNA\n" +
"Imb4LsVuSqxA6NwSj7cpRekgTedrhLFPJ+Ydb5MCgYEAsM3Q7OjILcIg0t6uht9e\n" +
"vrlwTsz1mtCV2co2I6crzdj9HeI2vqf1KAElDt6G7PUHhglcr/yjd8uEqmWRPKNX\n" +
"ddnnfVZB10jYeP/93pac6z/Zmc3iU4yKeUe7U10ZFf0KkiiYDQd59CpLef/2XScS\n" +
"HB0oRofnxRQjfjLc4muNT+ECgYEAlcDk06MOOTly+F8lCc1bA1dgAmgwFd2usDBd\n" +
"Y07a3e0HGnGLN3Kfl7C5i0tZq64HvxLnMd2vgLVxQlXGPpdQrC1TH+XLXg+qnlZO\n" +
"ivSH7i0/gx75bHvj75eH1XK65V8pDVDEoSPottllAIs21CxLw3N1ObOZWJm2EfmR\n" +
"cuHICmsCgYAtFJ1idqMoHxES3mlRpf2JxyQudP3SCm2WpGmqVzhRYInqeatY5sUd\n" +
"lPLHm/p77RT7EyxQHTlwn8FJPuM/4ZH1rQd/vB+Y8qAtYJCexDMsbvLW+Js+VOvk\n" +
"jweEC0nrcL31j9mF0vz5E6tfRu4hhJ6L4yfWs0gSejskeVB/w8QY4g==\n";

      privateKeyPkcs8 =
"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQINwot3btbWkUCAggA\n" +
"MBQGCCqGSIb3DQMHBAg6anV8j085cASCBMhUhNxb+sBuPj76dbsHqnuZybQF9q9G\n" +
"yvyrhZ5wpuslkEI8Iw5c/d7C721BzOoLLU6ip4bEAfB+0HtO4qWhlFmUAkw+d0km\n" +
"6Zw9PbkldNG8zHxTLrm7idz2hixnV5SYY+3MeaMbDWBazjxTKJZHakHodZ03di6S\n" +
"+EhLlZGKTWdtGwXvYrdbGGX7psnrq6Gh+oJyKz8swVZYT5c3Ta1q/r7dTBsN20Su\n" +
"rZVCWXwqF9JM77RxiilYtlqBm1/jR/6Y6Hsa7V20WfENmUWkPj5nN6/0JSg3Ohs6\n" +
"iLI+RN01hBxEhh2BIOg7A5aJrJvw5Y36oTKN6NfN+jKtd/xVX4OTnjJWAu07sxe4\n" +
"/gzvjCLTiZV840iuHzjYLhiKU1gcAq0HdVmStJG0KKL//QwoQZWSB+ezqaUrRqM0\n" +
"j/yF8yeNljf3d102alCjOlDd+WzntZGkh2qgOEdamDWTLnUV05FsFsgvQxi4/eH8\n" +
"aUzaLja8Ejf2DdkrzVtn3rZBqIIduv20tJept6XJdnkVfN4aQn6djgC07/wZawYv\n" +
"WO/9XPZVTamBs6/6rm72pPUsnlashJmdWR2GYQQsrGiqAx5pSkiRUK5o5YtYAYFq\n" +
"cTEkHOPuLr4xEkkxuJr9WcBn1xzVXTY0jOUdSQsN4n0UC1deS1Vtt0l3ETlclhV1\n" +
"WGf6gPb5Y2WSY7Gxn2s5goGVpdEr5WYF6zfUwBsM9U40u5NAuq6q0NrIVoVguGhP\n" +
"/GpxQrN8QPWvKtLJUKRtepWK6FLejcwGdDVaKYWF2qiK8bLPW2R1ZWbt18tjfcSV\n" +
"LDEFhbNZrQAbQKukVL7g6RNk2ZE2ZQOWcP1VihyX9h+h6iZBJQQJVSUht2P9omKP\n" +
"vXchMFGhb6e0VSxbb4Nw7Yq2/tEVwZGXsnKFEzyS2LkP2biqEHbjXtI1hreTxhOt\n" +
"zz/zXz/4AMl1MJEf0SpJ7Yaowl5lsSo2qoFJTwV6nK2YI25e80dcNMAWzAXokCDN\n" +
"GX4Iio411w9ZWIKrtiHnkDh1+u/ktLrRY/vwVtXIokzIo99UwTWcCtIJYktzmYp1\n" +
"L0E8EgurD/lFV4jGHMU0Q0ufxikteGXjAgA56F29xo879HDTn6+EsMvRLFhV7e38\n" +
"8ntTLNXa4uSF4pub2oltWEFRewCQaprKgCzG8cVs3fl5yHISYC9bsSLOVkjE2PPR\n" +
"avNFBV0W5BorX+A+ujYbfA54/EGTZfYtgt8TgkcAWY9ZVozrx8mQV5Z0CcDcNmHr\n" +
"S9IHlwAV1rKImH0l72lEUoObfNsB3ZYstgWPA7LY0Ir1GgSD1ArFJcIn0ZyNaq9/\n" +
"UhctA/83oybq/dpKIkgyppuyF1QihC0LiARRdTQypkvtpCrIMYeOm12NIpU14eO4\n" +
"AiHAMvZN2r++a6n43x/MFm82rnCXjwTIp6qwF43q2l36Af/acRFxxiQsUk7yr/fy\n" +
"rG5ILv3+vJN1/GcAh1uBezvMG50eIPmFkB1t+5unLezwFpyJ9CyfD6Hb3cZ0Ae0y\n" +
"nXZKRy1psgDy0jDAtmzyOO0+aT45tlA0nRwG7R3CvgKn33EkcaYT5NZ+47y0LDfW\n" +
"73yeM6F0A9SuqWUNp/QFT0/tqgqoG1blsi2tV4V5RBtt80BhDqx4XxW0nCp9MWS4\n" +
"/4Q=\n";

      privateKeyPkcs8Unencrypted =
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDRYzX9aEDHIu0\n" +
"SqyIAmBYNla7ORil5hV155lypFnPN9GAFBOw2jNLm3gefBNmHDBdsfuTdA3SRFNX\n" +
"zbpehvCzeKKCiGcz3JMr4oqJrI+EgCb/7kcZPpKAUmFiGqjX+6lZ256iOKXpE/j8\n" +
"CBq8eGinGUBVuTob1V1WeVBxDlm/Q5waLvdz4SdgP9iBRFgZKeBSL9ieyHvv2nZT\n" +
"r3+172BnAgvk+4T0GI7ojf1wv3PsQrVJ9mE5a8N7+oftiEP8EfBxaK3wWNHDDWCX\n" +
"BFVMmwD2sfnzKdoCLHS1xH+cExEtRf57etREeDpRtKMlt1v2qYozV9MYcpTMv/mk\n" +
"wbq4FTTLAgMBAAECggEANCRyQ4iXghkxROdbwsW/rE52QnAwoLwbpuw9EVvJj4e8\n" +
"LZMu3t6lK99L5/gBxhZo49wO7YTj2+3aw2twBKXLyGDCJFEAHd0cf29yxuiJOjxu\n" +
"LZEW8yq+O/3De0rbIzFUO2ZlqbOuudpXdhVD7mfIqjYX88wONDh5QAoM7OOEG4oe\n" +
"xkFMWcDUwU0j5QqPlfhinrgMWYqXFNf9TZvDNXLCjmHPHZSHDnWOaguWzhhS8wlc\n" +
"PTBblm1hG4+iBe9dv+h/15//bT/BTXVYUqBdviB9HzNRdpdLWxdydWbf7bi8iz10\n" +
"ClTDKS6jKM6rFapwdF5zZBPYXFUaQUStrN4I9riswQKBgQDljwLLCiYhxOB6sUYU\n" +
"J4wcmvydAapjZX+jAVveT2ZpzM+cL2nhr1FzmzMvED0UxgXG6tBkwFZIQbYlLUdH\n" +
"aaeOKDHxQqNgwv8D6u++Nk4x7gzpLLaCCHhKQtkqlZPONN7TsHIz+Pm/9KM1mFYA\n" +
"buzDj8uY8ZFCTAm/4pmEaiO46QKBgQDZw4VPpwlG/qS/NPP1LQI5k5Wb564mH8Fe\n" +
"nugCwCZs186lyQ8zOodfLz/Cl0qXoABwHns67O2U19XUPuq9vPsm5GVjBDRwR8GB\n" +
"tk9zPWnXwccNeHCfntk9vwbfdiH06aDQc0AiZvguxW5KrEDo3BKPtylF6SBN52uE\n" +
"sU8n5h1vkwKBgQCwzdDs6MgtwiDS3q6G316+uXBOzPWa0JXZyjYjpyvN2P0d4ja+\n" +
"p/UoASUO3obs9QeGCVyv/KN3y4SqZZE8o1d12ed9VkHXSNh4//3elpzrP9mZzeJT\n" +
"jIp5R7tTXRkV/QqSKJgNB3n0Kkt5//ZdJxIcHShGh+fFFCN+Mtzia41P4QKBgQCV\n" +
"wOTTow45OXL4XyUJzVsDV2ACaDAV3a6wMF1jTtrd7QcacYs3cp+XsLmLS1mrrge/\n" +
"Eucx3a+AtXFCVcY+l1CsLVMf5cteD6qeVk6K9IfuLT+DHvlse+Pvl4fVcrrlXykN\n" +
"UMShI+i22WUAizbULEvDc3U5s5lYmbYR+ZFy4cgKawKBgC0UnWJ2oygfERLeaVGl\n" +
"/YnHJC50/dIKbZakaapXOFFgiep5q1jmxR2U8seb+nvtFPsTLFAdOXCfwUk+4z/h\n" +
"kfWtB3+8H5jyoC1gkJ7EMyxu8tb4mz5U6+SPB4QLSetwvfWP2YXS/PkTq19G7iGE\n" +
"novjJ9azSBJ6OyR5UH/DxBji\n";

      publicKeyEncoding =
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0WM1/WhAxyLtEqsiAJg\n" +
"WDZWuzkYpeYVdeeZcqRZzzfRgBQTsNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobw\n" +
"s3iigohnM9yTK+KKiayPhIAm/+5HGT6SgFJhYhqo1/upWdueojil6RP4/AgavHho\n" +
"pxlAVbk6G9VdVnlQcQ5Zv0OcGi73c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9g\n" +
"ZwIL5PuE9BiO6I39cL9z7EK1SfZhOWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA\n" +
"9rH58ynaAix0tcR/nBMRLUX+e3rURHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0\n" +
"ywIDAQAB\n";
    }
  }

  class EcKeyTestData extends KeyTestData {
    public EcKeyTestData()
    {
      keyParams = new EcKeyParams();

      privateKeyPkcs1 =
"MIIBaAIBAQQgRxwcbzK9RV6AHYFsDcykI86o3M/a1KlJn0z8PcLMBZOggfowgfcC\n" +
"AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////\n" +
"MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr\n" +
"vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE\n" +
"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W\n" +
"K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8\n" +
"YyVRAgEBoUQDQgAEaG4WJuDAt0QkEM4t29KDUdzkQlMPGrqWzkWhgt9OGnwc6O7A\n" +
"ZLPSrDyhwyrKS7XLRXml5DisQ93RvByll32y8A==\n";

      privateKeyPkcs8 =
"MIIBwzA9BgkqhkiG9w0BBQ0wMDAbBgkqhkiG9w0BBQwwDgQIVHkBzLGtDvICAggA\n" +
"MBEGBSsOAwIHBAhk6g9eI3toNwSCAYDd+LWPDBTrKV7vUyxTvDbpUd0eXfh73DKA\n" +
"MHkdHuVmhpmpBbsF9XvaFuL8J/1xi1Yl2XGw8j3WyrprD2YEhl/+zKjNbdTDJmNO\n" +
"SlomuwWb5AVCJ9reT94zIXKCnexUcyBFS7ep+P4dwuef0VjzprjfmnAZHrP+u594\n" +
"ELHpKwi0ZpQLtcJjjud13bn43vbXb+aU7jmPV5lU2XP8TxaQJiYIibNEh1Y3TZGr\n" +
"akJormYvhaYbiZkKLHQ9AvQMEjhoIW5WCB3q+tKZUKTzcQpjNnf9FOTeKN3jk3Kd\n" +
"2OmibPZcbMJdgCD/nRVn1cBo7Hjn3IMjgtszQHtEUphOQiAkOJUnKmy9MTYqtcNN\n" +
"6cuFItbu4QvbVwailgdUjOYwIJCmIxExlPV0ohS24pFGsO03Yn7W8rBB9VWENYmG\n" +
"HkZIbGsHv7O9Wy7fv+FJgZkjeti0807IsNXSJl8LUK0ZIhAR7OU8uONWMsbHdQnk\n" +
"q1HB1ZKa52ugACl7g/DF9b7CoSAjFeE=\n";

      publicKeyEncoding =
"MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA\n" +
"AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////\n" +
"///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd\n" +
"NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5\n" +
"RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA\n" +
"//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABGhuFibgwLdEJBDOLdvSg1Hc\n" +
"5EJTDxq6ls5FoYLfThp8HOjuwGSz0qw8ocMqyku1y0V5peQ4rEPd0bwcpZd9svA=\n";
    }
  }

  RsaKeyTestData rsaKeyTestData;
  EcKeyTestData ecKeyTestData;

  // debug KeyTestData[] keyTestData = new KeyTestData[2];
  KeyTestData[] keyTestData = new KeyTestData[1];
  
  @Before
  public void
  setUp() throws EncodingException, CertificateV2.Error
  {
    rsaKeyTestData = new RsaKeyTestData();
    ecKeyTestData = new EcKeyTestData();

    keyTestData[0] = rsaKeyTestData;
    // debug keyTestData[1] = ecKeyTestData;
  }

  @Test
  public void
  testSaveLoad() throws TpmPrivateKey.Error
  {
    for (KeyTestData dataSet : keyTestData) {
      // Load the key in PKCS #1 format.
      byte[] pkcs1 = Common.base64Decode(dataSet.privateKeyPkcs1);
      TpmPrivateKey key1 = new TpmPrivateKey();
      try {
        key1.loadPkcs1(ByteBuffer.wrap(pkcs1));
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }

      // Save the key in PKCS #1 format.
      Blob savedPkcs1Key = null;
      try {
        savedPkcs1Key = key1.toPkcs1();
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertTrue(savedPkcs1Key.equals(new Blob(pkcs1)));

      // Load the key in unencrypted PKCS #8 format.
      byte[] pkcs8 = Common.base64Decode(dataSet.privateKeyPkcs8Unencrypted);
      TpmPrivateKey key8 = new TpmPrivateKey();
      try {
        key8.loadPkcs8(ByteBuffer.wrap(pkcs8));
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }

      // Save the key in unencrypted PKCS #8 format.
      Blob savedPkcs8Key = null;
      try {
        savedPkcs8Key = key8.toPkcs8();
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertTrue(savedPkcs8Key.equals(new Blob(pkcs8)));

      ByteBuffer password = new Blob("password").buf();

      // Load the key in encrypted PKCS #8 format.
      byte[] encryptedPkcs8 = Common.base64Decode(dataSet.privateKeyPkcs8);
      TpmPrivateKey encryptedKey8 = new TpmPrivateKey();
      try {
        encryptedKey8.loadEncryptedPkcs8(ByteBuffer.wrap(encryptedPkcs8), password);
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }

      // Save the key in encrypted PKCS #8 format and resave as unencrypted.
      Blob savedEncryptedPkcs8Key = null;
      try {
        savedEncryptedPkcs8Key = encryptedKey8.toEncryptedPkcs8(password);
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      key8 =  new TpmPrivateKey();
      key8.loadEncryptedPkcs8(savedEncryptedPkcs8Key.buf(), password);
      Blob resavedPkcs8Key = key8.toPkcs8();
      assertTrue(resavedPkcs8Key.equals(new Blob(pkcs8)));
    }
  }

  @Test
  public void
  testDerivePublicKey() throws TpmPrivateKey.Error
  {
    for (KeyTestData dataSet : keyTestData) {
      byte[] pkcs8 = Common.base64Decode(dataSet.privateKeyPkcs8Unencrypted);
      TpmPrivateKey key = new TpmPrivateKey();
      try {
        key.loadPkcs8(ByteBuffer.wrap(pkcs8));
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }

      // Derive the public key and compare.
      Blob publicKeyBits = key.derivePublicKey();
      byte[] expected = Common.base64Decode(dataSet.publicKeyEncoding);
      assertTrue(publicKeyBits.equals(new Blob(expected)));
    }
  }

  @Test
  public void
  testRsaDecryption() throws TpmPrivateKey.Error
  {
    KeyTestData dataSet = rsaKeyTestData;

    byte[] pkcs8 = Common.base64Decode(dataSet.privateKeyPkcs8Unencrypted);
    TpmPrivateKey key = new TpmPrivateKey();
    key.loadPkcs8(ByteBuffer.wrap(pkcs8));

    Blob plainText = new Blob(new int[] {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    });

    String cipherTextBase64 =
      "i2XNpZ2JbLa4JmBTdDrGmsd4/0C+p+BSCpW3MuPBNe5uChQ0eRO1dvjTnEqwSECY\n" +
      "38en9JZwcyb0It/TSFNXHlq+Z1ZpffnjIJxQR9HcgwvwQJh6WRH0vu38tvGkGuNv\n" +
      "60Rdn85hqSy1CikmXCeWXL9yCqeqcP21R94G/T3FuA+c1FtFko8KOzCwvrTXMO6n\n" +
      "5PNsqlLXabSGr+jz4EwOsSCgPkiDf9U6tXoSPRA2/YvqFQdaiUXIVlomESvaqqZ8\n" +
      "FxPs2BON0lobM8gT+xdzbRKofp+rNjNK+5uWyeOnXJwzCszh17cdJl2BH1dZwaVD\n" +
      "PmTiSdeDQXZ94U5boDQ4Aw==\n";

    byte[] cipherText = Common.base64Decode(cipherTextBase64);

    Blob decryptedText = key.decrypt(ByteBuffer.wrap(cipherText));

    assertTrue(decryptedText.equals(plainText));
  }

  @Test
  public void
  testGenerateKey() 
    throws TpmPrivateKey.Error, UnrecognizedKeyFormatException,
      NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
      SignatureException
  {
    for (KeyTestData dataSet : keyTestData) {
      TpmPrivateKey key = TpmPrivateKey.generatePrivateKey(dataSet.keyParams);
      Blob publicKeyBits = key.derivePublicKey();

      Blob data = new Blob(new int[] {0x01, 0x02, 0x03, 0x04});

      // Sign and verify.
      Blob signature = key.sign(data.buf(), DigestAlgorithm.SHA256);

      boolean result = VerificationHelpers.verifySignature
        (data, signature, new PublicKey(publicKeyBits));
      assertTrue(result);

      // Check that another generated private key is different.
      TpmPrivateKey key2 = TpmPrivateKey.generatePrivateKey(dataSet.keyParams);
      assertTrue(!key.toPkcs8().equals(key2.toPkcs8()));
    }
  }
}
