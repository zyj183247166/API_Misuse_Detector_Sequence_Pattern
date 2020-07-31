package com.cuspycode.jpacrypt;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.*;
import java.net.*;
import org.json.*;
import java.security.KeyStore;
import java.sql.*;
import org.jsoup.*;
import org.quartz.*;
import javax.crypto.spec.*;
import org.mozilla.javascript.*;
import javax.crypto.SecretKeyFactory;
import org.kohsuke.args4j.spi.Parameters;
import static android.os.Environment.MEDIA_MOUNTED;
import org.apache.commons.lang.text.StrBuilder;
import org.apache.commons.math3.geometry.euclidean.threed.*;
import android.app.ListFragment;
import android.app.ListView;
import org.apache.jackrabbit.core.config.*;
import org.apache.jackrabbit.core.fs.*;
import org.apache.jackrabbit.jcr2spi.*;
import android.content.Intent;
import android.content.SharedPreferences;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import android.preference.PreferenceManager;
import android.content.pm.*;
import android.database.*;
import android.database.sqlite.SQLiteDatabase;
import android.app.*;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import org.apache.jackrabbit.core.state.PropertyState;
import org.apache.jackrabbit.core.util.DOMWalker;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.io.*;
import java.io.File;
import java.util.*; 
import org.joda.time.*;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import org.apache.jackrabbit.core.state.*;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.util.Properties;
import com.google.javascript.rhino.jstype.*;
import org.joda.time.contrib.hibernate.PersistentDateTime;
import android.os.Environment;
import static org.junit.Assert.assertEquals;
import org.apache.gora.util.WritableUtils;
import org.junit.Test;
import javax.crypto.Cipher;        
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import com.alibaba.druid.util.Base64;
import com.alibaba.druid.util.JdbcUtils;
import org.apache.commons.httpclient.auth.*;
import org.apache.commons.logging.*;
import org.apache.jackrabbit.server.io.*;
import org.apache.jackrabbit.core.state.*;
import org.apache.jackrabbit.core.*;
import org.apache.jackrabbit.jcr2spi.hierarchy.*;
import org.jfree.chart.entity.*;
import org.jfree.chart.ChartRenderingInfo;
import org.jfree.chart.plot.*;
import org.jfree.data.statistics.*;
import org.jfree.chart.plot.*;
import org.apache.lucene.index.*;
import android.content.*;
import org.wordpress.android.util.*;
import android.content.res.TypedArray;
import android.os.*;
import org.apache.http.client.*;
import org.apache.http.*;
import javax.servlet.http.*;
import org.apache.commons.configuration2.*;
import javax.crypto.spec.IvParameterSpec;
public class allAPIBugs_xiaojie {
    
    public allAPIBugs_xiaojie() {
        
    }

    public static String bug_1(byte[] keyBytes, String plainText)
            throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedString = Base64.byteArrayToBase64(encryptedBytes);

        return encryptedString;
    }
    
    public static String bug_1_repair(byte[] keyBytes, String plainText)
            throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        } catch (InvalidKeyException e) {
            //For IBM JDK, 鍘熷洜璇风湅瑙ｅ瘑鏂规硶涓殑璇存槑
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());
            Key publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        }
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedString = Base64.byteArrayToBase64(encryptedBytes);

        return encryptedString;
    }

    public static String bug_2(PublicKey publicKey, String cipherText)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        try {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            // for ibm jdk
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
            Key fakePublicKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
            cipher.init(Cipher.DECRYPT_MODE, fakePublicKey);
        }
        
        if (cipherText == null || cipherText.length() == 0) {
            return cipherText;
        }

        byte[] cipherBytes = Base64.base64ToByteArray(cipherText);
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        return new String(plainBytes);
    }

    public static String bug_2_repair(PublicKey publicKey, String cipherText)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        try {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            // 鍥犱负 IBM JDK 涓嶆敮鎸佺閽ュ姞瀵�, 鍏挜瑙ｅ瘑, 鎵�浠ヨ鍙嶈浆鍏閽�
            // 涔熷氨鏄瀵逛簬瑙ｅ瘑, 鍙互閫氳繃鍏挜鐨勫弬鏁颁吉閫犱竴涓閽ュ璞℃楠� IBM JDK
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
            Key fakePrivateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
            cipher = Cipher.getInstance("RSA"); //It is a stateful object. so we need to get new one.
            cipher.init(Cipher.DECRYPT_MODE, fakePrivateKey);
        }
        
        if (cipherText == null || cipherText.length() == 0) {
            return cipherText;
        }

        byte[] cipherBytes = Base64.base64ToByteArray(cipherText);
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        return new String(plainBytes);
    }
    private Cipher          m_cipher = null;
    public String bug_3(String value)
    {
        String clearText = value;
        if (clearText == null)
            clearText = "";
        //  Init
        if (m_cipher == null)
            initCipher();
        //  Encrypt
        if (m_cipher != null)
        {
            try
            {
                m_cipher.init(Cipher.ENCRYPT_MODE, m_key);
                byte[] encBytes = m_cipher.doFinal(clearText.getBytes());
                String encString = convertToHexString(encBytes);
                // globalqss - [ 1577737 ] Security Breach - show database password
                // log.log (Level.ALL, value + " => " + encString);
                return encString;
            }
            catch (Exception ex)
            {
                // log.log(Level.INFO, value, ex);
                log.log(Level.INFO, "Problem encrypting string", ex);
            }
        }
        //  Fallback
        return CLEARVALUE_START + value + CLEARVALUE_END;
    }

    public String bug_3_repair(String value)
    {
        String clearText = value;
        if (clearText == null)
            clearText = "";
        //  Init
        if (m_cipher == null)
            initCipher();
        //  Encrypt
        if (m_cipher != null)
        {
            try
            {
                m_cipher.init(Cipher.ENCRYPT_MODE, m_key);
                byte[] encBytes = m_cipher.doFinal(clearText.getBytes("UTF8"));
                String encString = convertToHexString(encBytes);
                // globalqss - [ 1577737 ] Security Breach - show database password
                // log.log (Level.ALL, value + " => " + encString);
                return encString;
            }
            catch (Exception ex)
            {
                // log.log(Level.INFO, value, ex);
                log.log(Level.INFO, "Problem encrypting string", ex);
            }
        }
        //  Fallback
        return CLEARVALUE_START + value + CLEARVALUE_END;
    }



    public String bug_4(String value)
    {
        if (value == null || value.length() == 0)
            return value;
        boolean isEncrypted = value.startsWith(ENCRYPTEDVALUE_START) && value.endsWith(ENCRYPTEDVALUE_END);
        if (isEncrypted)
            value = value.substring(ENCRYPTEDVALUE_START.length(), value.length()-ENCRYPTEDVALUE_END.length());
        //  Needs to be hex String  
        byte[] data = convertHexString(value);
        if (data == null)   //  cannot decrypt
        {
            if (isEncrypted)
            {
                // log.info("Failed: " + value);
                log.info("Failed");
                return null;
            }
            //  assume not encrypted
            return value;
        }
        //  Init
        if (m_cipher == null)
            initCipher();

        //  Encrypt
        if (m_cipher != null && value != null && value.length() > 0)
        {
            try
            {
                AlgorithmParameters ap = m_cipher.getParameters();
                m_cipher.init(Cipher.DECRYPT_MODE, m_key, ap);
                byte[] out = m_cipher.doFinal(data);
                String retValue = new String(out);
                // globalqss - [ 1577737 ] Security Breach - show database password
                // log.log (Level.ALL, value + " => " + retValue);
                return retValue;
            }
            catch (Exception ex)
            {
                // log.info("Failed: " + value + " - " + ex.toString());
                log.info("Failed decrypting " + ex.toString());
            }
        }
        return null;
    }
    public String bug_4_repair(String value)
    {
        if (value == null || value.length() == 0)
            return value;
        boolean isEncrypted = value.startsWith(ENCRYPTEDVALUE_START) && value.endsWith(ENCRYPTEDVALUE_END);
        if (isEncrypted)
            value = value.substring(ENCRYPTEDVALUE_START.length(), value.length()-ENCRYPTEDVALUE_END.length());
        //  Needs to be hex String  
        byte[] data = convertHexString(value);
        if (data == null)   //  cannot decrypt
        {
            if (isEncrypted)
            {
                // log.info("Failed: " + value);
                log.info("Failed");
                return null;
            }
            //  assume not encrypted
            return value;
        }
        //  Init
        if (m_cipher == null)
            initCipher();

        //  Encrypt
        if (m_cipher != null && value != null && value.length() > 0)
        {
            try
            {
                AlgorithmParameters ap = m_cipher.getParameters();
                m_cipher.init(Cipher.DECRYPT_MODE, m_key, ap);
                byte[] out = m_cipher.doFinal(data);
                String retValue = new String(out,"UTF8");
                // globalqss - [ 1577737 ] Security Breach - show database password
                // log.log (Level.ALL, value + " => " + retValue);
                return retValue;
            }
            catch (Exception ex)
            {
                // log.info("Failed: " + value + " - " + ex.toString());
                log.info("Failed decrypting " + ex.toString());
            }
        }
        return null;
    }
    public synchronized static String bug_5(String callId) {
        try {
            // HMAC-SHA1 operation
            SecretKeySpec sks = new SecretKeySpec(secretKey, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(sks);
            byte[] contributionId = mac.doFinal(callId.getBytes());
            // Convert to Hexa and keep only 128 bits
            StringBuilder hexString = new StringBuilder(32);
            for (int i = 0; i < 16 && i < contributionId.length; i++) {
                String hex = Integer.toHexString(0xFF & contributionId[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            

            String id = hexString.toString();
            return id;
        } catch(Exception e) {
            return null;
        }
    }


    public synchronized static String bug_5_repair(String callId) {
        try {
            // HMAC-SHA1 operation
            SecretKeySpec sks = new SecretKeySpec(secretKey, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(sks);
            byte[] contributionId = mac.doFinal(callId.getBytes("UTF8"));

            // Convert to Hexa and keep only 128 bits
            StringBuilder hexString = new StringBuilder(32);
            for (int i = 0; i < 16 && i < contributionId.length; i++) {
                String hex = Integer.toHexString(0xFF & contributionId[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            

            String id = hexString.toString();
            return id;
        } catch(Exception e) {
            return null;
        }
    }

      static long bug_6(long l) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
          dos.writeLong(l);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        return encoder.decodeLong(baos.toByteArray());
      }


      static long bug_6_repair(long l) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
          dos.writeLong(l);
          dos.flush();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        return encoder.decodeLong(baos.toByteArray());
      }
      static long bug_6_1(long l) {
        Properties props = new Properties();
        props.put("keyBlah", "valueBlah");
        props.put("keyBlah2", "valueBlah2");
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutput out = new DataOutputStream(bos);
        WritableUtils.writeProperties(out, props);

        DataInput in = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));

        Properties propsRead = WritableUtils.readProperties(in);
        
        assertEquals(propsRead.get("keyBlah"), props.get("keyBlah"));
        assertEquals(propsRead.get("keyBlah2"), props.get("keyBlah2"));
      }
      
      static long bug_6_1_repair(long l) {
        Properties props = new Properties();
        props.put("keyBlah", "valueBlah");
        props.put("keyBlah2", "valueBlah2");
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutput out = new DataOutputStream(bos);
        WritableUtils.writeProperties(out, props);
        ((DataOutputStream)out).flush();

        DataInput in = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));

        Properties propsRead = WritableUtils.readProperties(in);
        
        assertEquals(propsRead.get("keyBlah"), props.get("keyBlah"));
        assertEquals(propsRead.get("keyBlah2"), props.get("keyBlah2"));
    }



    public void bug_7(String ptString)
    {
        // Format is "PT: %d(%s)"
        if (ptString == null || ptString.length() == 0)
        {
            this.pt = null;
            return;
        }

        if (ptString.indexOf('(') > 0)
        {
            this.pt = Long.parseLong(ptString.substring(0, ptString.indexOf('(')));
        }
        else{
                this.pt = Long.parseLong(ptString);
        }
    }

    public void bug_7_repair(String ptString)
    {
        // Format is "PT: %d(%s)"
        if (ptString == null || ptString.length() == 0)
        {
            this.pt = null;
            return;
        }

       
        try
        {
            if (ptString.indexOf('(') > 0){
                this.pt = Long.parseLong(ptString.substring(0, ptString.indexOf('(')));    
            }
            else{
                this.pt = Long.parseLong(ptString);
            }
            
        }catch (NumberFormatException e)
        {
            throw new NumberFormatException(String.format("Input string [%s] is not a parsable long", ptString));
        }
    }
    public void bug_8(String pattern){
         Date date = new Date();
         SimpleDateFormat formatter = new SimpleDateFormat(pattern);
         return formatter.format(date);
    }
    public void bug_8_repair(String pattern){
         Date date = new Date();
         SimpleDateFormat formatter = new SimpleDateFormat(pattern);
         formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
         return formatter.format(date);
    }
    public void bug_9(String key, String separator) {
        List<Byte> parts = new ArrayList<>();
        for (String value : getKey(key).split(separator))
            parts.add(Byte.parseByte(value.trim()));
        return parts;
    }
    public void bug_9_repair(String key, String separator) {
        List<Byte> parts = new ArrayList<>();
        try {
            for (String value : getKey(key).split(separator))
                parts.add(Byte.parseByte(value.trim()));
            return parts;
        } catch (NumberFormatException e) {
            throw new NumberFormatException(String.format("Configuration value [%s] is not a parsable byte", key));
        }
    }

    public short bug_10(String key) {
        return Short.parseShort(getKey(key));
    }
    public short bug_10_repair(String key) {
        try {
            return Short.parseShort(getKey(key));
        } catch (NumberFormatException e) {
            throw new NumberFormatException(String.format("Configuration value [%s] is not a parsable short", key));
        }
    }
    protected ClusterConfig bug_11(Element parent)
         throws ConfigurationException {

         NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
        Node child = children.item(i);
           if (child.getNodeType() == Node.ELEMENT_NODE
                   && CLUSTER_ELEMENT.equals(child.getNodeName())) {
                Element element = (Element) child;
                String id = ConfigurationParser.getAttribute(element, ID_ATTRIBUTE, null);
                long syncDelay = Long.parseLong(ConfigurationParser.getAttribute(element, SYNC_DELAY_ATTRIBUTE, DEFAULT_SYNC_DELAY));
 
               JournalConfig jc = parseJournalConfig(element);
                return new ClusterConfig(id, syncDelay, jc);
             }
        }
        return null;
     }
    protected ClusterConfig bug_11_repair(Element parent)
         throws ConfigurationException {

        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
        Node child = children.item(i);
           if (child.getNodeType() == Node.ELEMENT_NODE
                   && CLUSTER_ELEMENT.equals(child.getNodeName())) {
                Element element = (Element) child;

               String value = ConfigurationParser.getAttribute(element, ID_ATTRIBUTE, null);
               String id = ConfigurationParser.replaceVariables(value);
                value = ConfigurationParser.getAttribute(element, SYNC_DELAY_ATTRIBUTE, DEFAULT_SYNC_DELAY);
                long syncDelay = Long.parseLong(ConfigurationParser.replaceVariables(value));
 
               JournalConfig jc = parseJournalConfig(element);
                return new ClusterConfig(id, syncDelay, jc);
             }
        }
        return null;
     }


     private void bug_12(InputStream in, boolean temp) throws IOException {
          byte[] spoolBuffer = new byte[0x2000];
          int read;
            int len = 0;
            OutputStream out = null;
           File spoolFile = null;
           try {
               while ((read = in.read(spoolBuffer)) > 0) {
                   if (out != null) {
                        // spool to temp file
                         out.write(spoolBuffer, 0, read);
                        len += read;
                    } else if (len + read > BinaryQValue.MAX_BUFFER_SIZE) {
                         // threshold for keeping data in memory exceeded;
                         // create temp file and spool buffer contents
                        TransientFileFactory fileFactory = TransientFileFactory.getInstance();
                        spoolFile = fileFactory.createTransientFile("bin", null, null);
                       out = new FileOutputStream(spoolFile);
                         out.write(buffer, 0, len);
                        out.write(spoolBuffer, 0, read);
                         buffer = null;
                         len += read;
                     } else {
                         // reallocate new buffer and spool old buffer contents
                         byte[] newBuffer = new byte[len + read];
                         System.arraycopy(buffer, 0, newBuffer, 0, len);
                         System.arraycopy(spoolBuffer, 0, newBuffer, len, read);
                         buffer = newBuffer;
                         len += read;
                     }
                 }
             } finally {
                
                 if (out != null) {
                     out.close();
                 }
             }
 
             // init vars
             file = spoolFile;
             this.temp = temp;
             // buffer is EMPTY_BYTE_ARRAY (default value)
         }
    private void bug_12_repair(InputStream in, boolean temp) throws IOException {
           byte[] spoolBuffer = new byte[0x2000];
          int read;
            int len = 0;
            OutputStream out = null;
           File spoolFile = null;
           try {
               while ((read = in.read(spoolBuffer)) > 0) {
                   if (out != null) {
                        // spool to temp file
                         out.write(spoolBuffer, 0, read);
                        len += read;
                    } else if (len + read > BinaryQValue.MAX_BUFFER_SIZE) {
                         // threshold for keeping data in memory exceeded;
                         // create temp file and spool buffer contents
                        TransientFileFactory fileFactory = TransientFileFactory.getInstance();
                        spoolFile = fileFactory.createTransientFile("bin", null, null);
                       out = new FileOutputStream(spoolFile);
                         out.write(buffer, 0, len);
                        out.write(spoolBuffer, 0, read);
                         buffer = null;
                         len += read;
                     } else {
                         // reallocate new buffer and spool old buffer contents
                         byte[] newBuffer = new byte[len + read];
                         System.arraycopy(buffer, 0, newBuffer, 0, len);
                         System.arraycopy(spoolBuffer, 0, newBuffer, len, read);
                         buffer = newBuffer;
                         len += read;
                     }
                 }
             } finally {
                in.close();
                 if (out != null) {
                     out.close();
                 }
             }
 
             // init vars
             file = spoolFile;
             this.temp = temp;
             // buffer is EMPTY_BYTE_ARRAY (default value)
    }
    private void bug_13(DOMWalker walker, PropertyState state,String MULTIVALUED_ATTRIBUTE){
        String multiValued = walker.getAttribute(MULTIVALUED_ATTRIBUTE);
        state.setMultiValued(Boolean.getBoolean(multiValued));
    }
    private void bug_13_repair(DOMWalker walker, PropertyState state,String MULTIVALUED_ATTRIBUTE){
        String multiValued = walker.getAttribute(MULTIVALUED_ATTRIBUTE);
        state.setMultiValued(Boolean.parseBoolean(multiValued));
    }
    private void bug_14(String prefix,NamespaceStorage storage){
        storage.unregisterNamespace(prefix);
    }
    private void bug_14_repair(String prefix,NamespaceStorage storage){
        storage.unregisterNamespace(storage.getURI(prefix));
    }
    public void bug_15(String propFilePath)
    {
        FileSystemResource propFile = new FileSystemResource(itemStateStore, propFilePath);
        try{
             propFile.delete(true);
        }catch (FileSystemException fse) {

        }
    }
    public void bug_15_repair(String propFilePath)
    {
        FileSystemResource propFile = new FileSystemResource(itemStateStore, propFilePath);
        try{
         if (propFile.exists()) {
             propFile.delete(true);
         }
        }catch (FileSystemException fse) {

        }
    }
    public void bug_16_needRefactor(String dirPath)//needRefactor琛ㄧず涓嶄竴瀹氭槸缂洪櫡锛屽湪鏌愪簺鎯呭喌涓嬫槸缂洪櫡锛屼絾鏄垜浠渶瑕佹湞鐫�鏇村ソ鐨勬柟鍚戦噸鏋�
    {
        File envDir = new File(dirPath);
        if (!envDir.exists()){
                envDir.mkdir();
        }
    }    

    public void bug_16_repair_needRefactor(String dirPath)
    {
        File envDir = new File(dirPath);
        if (!envDir.exists()){
                envDir.mkdirs();
        }
    }

    private void bug_17(DataInputStream in, byte[] rapdu) throws IOException, GeneralSecurityException {
 
       int length = in.readUnsignedByte();
       if (length != 8) {
          throw new IllegalStateException("DO'8E wrong length");
       }
       byte[] cc1 = new byte[8];
       in.readFully(cc1);
        mac.init(ksMac);
       ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out); 
       ssc++;
       dataOut.writeLong(ssc);
       byte[] paddedData = Util.pad(rapdu, 0, rapdu.length - 2 - 8 - 2);
       dataOut.write(paddedData, 0, paddedData.length);
       dataOut.flush();
        mac.init(ksMac);
       byte[] cc2 = mac.doFinal(out.toByteArray());
       if (!Arrays.equals(cc1, cc2)) {
          throw new IllegalStateException("Incorrect MAC!");
       }
    }
    private void bug_17_repair(DataInputStream in, byte[] rapdu) throws IOException, GeneralSecurityException {
 
       int length = in.readUnsignedByte();
       if (length != 8) {
          throw new IllegalStateException("DO'8E wrong length");
       }
       byte[] cc1 = new byte[8];
       in.readFully(cc1);
        mac.init(ksMac);
       ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out); 
       ssc++;
       dataOut.writeLong(ssc);
       byte[] paddedData = Util.pad(rapdu, 0, rapdu.length - 2 - 8 - 2);
       dataOut.write(paddedData, 0, paddedData.length);
       dataOut.flush();
        mac.init(ksMac);
       byte[] cc2 = mac.doFinal(out.toByteArray());
        dataOut.close();
       if (!Arrays.equals(cc1, cc2)) {
          throw new IllegalStateException("Incorrect MAC!");
       }
    }

    public void bug_18() throws Exception {
        DateMidnight test = new DateMidnight(TEST_TIME_NOW_UTC);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(test);

        byte[] bytes = baos.toByteArray();
        oos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        DateMidnight result = (DateMidnight) ois.readObject();
        ois.close();
        assertEquals(test, result);
    }
    public void bug_18_repair() throws Exception {
        DateMidnight test = new DateMidnight(TEST_TIME_NOW_UTC);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(test);
        oos.close();
        byte[] bytes = baos.toByteArray();
        
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        DateMidnight result = (DateMidnight) ois.readObject();
        ois.close();
        assertEquals(test, result);
    }
    public void bug_19() throws IOException {
        SortedMap fieldToReader = new TreeMap();
        field = (String)fieldToReader.firstKey();
        if (field != null)
            termEnum = ((IndexReader)fieldToReader.get(field)).terms();
    }
    public void bug_19_repair() throws IOException {
        SortedMap fieldToReader = new TreeMap();
        try{
                field = (String)fieldToReader.firstKey();    
        }catch(NoSuchElementException e) {
            return;
        }
        
        if (field != null)
            termEnum = ((IndexReader)fieldToReader.get(field)).terms();
    }

    public Data bug_20_needRefactor(int id) {
        final PackageManager pm = getPackageManager();
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        Collections.sort(packages, new ApplicationInfo.DisplayNameComparator(pm));
        
        Data data = new Data();
        data.sections = new ArrayList<Section>();
        data.apps = new App[packages.size()];
        
        String lastSection = "";
        String currentSection;
        for(int i = 0; i < packages.size(); i++) {
            ApplicationInfo appInfo = packages.get(i);
            
            data.apps[i] = new App();
            data.apps[i].name = (String) appInfo.loadLabel(pm);
            data.apps[i].packageName = appInfo.packageName;
            data.apps[i].icon = appInfo.loadIcon(pm);
            
            
            if(data.apps[i].name != null && data.apps[i].name.length() > 0) {
                currentSection = data.apps[i].name.substring(0, 1).toUpperCase();
                if(!lastSection.equals(currentSection)) {               
                    data.sections.add(new Section(i, currentSection));
                    lastSection = currentSection;
                }
            }
        }
    }
    public Data bug_20_repair_needRefactor(int id) {
        final PackageManager pm = getPackageManager();
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        Collections.sort(packages, new ApplicationInfo.DisplayNameComparator(pm));
        
        Data data = new Data();
        data.sections = new ArrayList<Section>();
        data.apps = new App[packages.size()];
        
        String lastSection = "";
        String currentSection;
        for(int i = 0; i < packages.size(); i++) {
            ApplicationInfo appInfo = packages.get(i);
            
            data.apps[i] = new App();
            data.apps[i].name = (String) appInfo.loadLabel(pm);
            data.apps[i].packageName = appInfo.packageName;
            
            try {
                data.apps[i].icon = appInfo.loadIcon(pm);
            } catch (OutOfMemoryError e) {
                data.apps[i].icon = this.getResources().getDrawable(R.drawable.sym_def_app_icon);
            }
            
            if(data.apps[i].name != null && data.apps[i].name.length() > 0) {
                currentSection = data.apps[i].name.substring(0, 1).toUpperCase();
                if(!lastSection.equals(currentSection)) {               
                    data.sections.add(new Section(i, currentSection));
                    lastSection = currentSection;
                }
            }
        }
    }

    public static void bug_21() throws FileNotFoundException {
            // Initialized the File and File Channel
            String FILER_LOCATION = "C:\\documents\\test";
        // This is a text message that to be written in filer location file.
            String MESSAGE_WRITE_ON_FILER = "Operation has been committed.";
            RandomAccessFile randomAccessFileOutputFile = null;
            FileChannel outputFileChannel = null;
            try {
                // Create a random access file with 'rw' permission..
                randomAccessFileOutputFile = new RandomAccessFile(FILER_LOCATION + File.separator + "readme.txt", "rw");
                outputFileChannel = randomAccessFileOutputFile.getChannel();
                //Read line of code one by one and converted it into byte array to write into FileChannel.
                final byte[] bytes = (MESSAGE_WRITE_ON_FILER + System.lineSeparator()).getBytes();
                // Defined a new buffer capacity.
                ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
                // Put byte array into butter array.
                buffer.put(bytes);
                // its flip the buffer and set the position to zero for next write operation.
                
                /**
                 * Writes a sequence of bytes to this channel from the given buffer.
                 */
                outputFileChannel.write(buffer);
                System.out.println("File Write Operation is done!!");

            } catch (IOException ex) {
                System.out.println("Oops Unable to proceed file write Operation due to ->" + ex.getMessage());
            } finally {
                try {
                    outputFileChannel.close();
                    randomAccessFileOutputFile.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
    }

    public static void bug_21_repair() throws FileNotFoundException {
            // Initialized the File and File Channel
            String FILER_LOCATION = "C:\\documents\\test";
        // This is a text message that to be written in filer location file.
            String MESSAGE_WRITE_ON_FILER = "Operation has been committed.";
            RandomAccessFile randomAccessFileOutputFile = null;
            FileChannel outputFileChannel = null;
            try {
                // Create a random access file with 'rw' permission..
                randomAccessFileOutputFile = new RandomAccessFile(FILER_LOCATION + File.separator + "readme.txt", "rw");
                outputFileChannel = randomAccessFileOutputFile.getChannel();
                //Read line of code one by one and converted it into byte array to write into FileChannel.
                final byte[] bytes = (MESSAGE_WRITE_ON_FILER + System.lineSeparator()).getBytes();
                // Defined a new buffer capacity.
                ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
                // Put byte array into butter array.
                buffer.put(bytes);
                // its flip the buffer and set the position to zero for next write operation.
                buffer.flip();
                /**
                 * Writes a sequence of bytes to this channel from the given buffer.
                 */
                outputFileChannel.write(buffer);
                System.out.println("File Write Operation is done!!");

            } catch (IOException ex) {
                System.out.println("Oops Unable to proceed file write Operation due to ->" + ex.getMessage());
            } finally {
                try {
                    outputFileChannel.close();
                    randomAccessFileOutputFile.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
    }

    public String bug_22(String currentToken, Scanner scanner) {

        String token = scanner.next();

    }
    public String bug_22_repair(String currentToken, Scanner scanner) {
        if (!scanner.hasNext()) {
            throw new IllegalArgumentException("Insufficient number of tokens to scan after closed parenthesis");
        }
        String token = scanner.next();
    }
    protected void bug_23(AnswerObject result,Dialog dialog) {
        if(outerCallingListActivity==null){
            dialog.setTitle(outerCallingActivity.getResources().getString(R.string.ui_calc));
            outerCallingActivity.onPostExecute(result);
        }
        else {
            dialog.setTitle(outerCallingListActivity.getResources().getString(R.string.ui_calc));
            outerCallingListActivity.onPostExecute(result);
        }
        dialog.dismiss();
    }
    protected void bug_23_repair(AnswerObject result,Dialog dialog) {
        if(outerCallingListActivity==null){
            dialog.setTitle(outerCallingActivity.getResources().getString(R.string.ui_calc));
            outerCallingActivity.onPostExecute(result);
        }
        else {
            dialog.setTitle(outerCallingListActivity.getResources().getString(R.string.ui_calc));
            outerCallingListActivity.onPostExecute(result);
        }
        if(dialog.isShowing())
            dialog.dismiss();
    }
    public int bug_24(long reportId,SQLiteDatabase mDb) {
        Cursor c = mDb.query(
            TABLE,
            array(STATE),
            WHERE,
            array(reportId),
            null,
            null,
            null
        );
        c.moveToFirst();
        return c.getInt(0);
        final int reportState = c.getInt(0);

        //free resources

        return reportState;
    }

        public int bug_24_repair(long reportId,SQLiteDatabase mDb) {
        Cursor c = mDb.query(
            TABLE,
            array(STATE),
            WHERE,
            array(reportId),
            null,
            null,
            null
        );
        if ( c.getCount() < 1 ){

            //free resources
            c.close();
            return STATE_NOT_OPENGEOSMS;
        }
        c.moveToFirst();
        return c.getInt(0);
        final int reportState = c.getInt(0);

        //free resources
        c.close();

        return reportState;
    }


        public StrBuilder bug_25(Object obj, int width, char padChar) {
           if (width > 0) {
              StrBuilder.getNullText();
              ensureCapacity(size + width);
              String str = (obj == null ? StrBuilder.getNullText() : obj.toString());
               int strLen = str.length();
                if (strLen >= width) {
                    str.getChars(strLen - width, strLen, buffer, size);
                } else {
                   int padLen = width - strLen;
                    for (int i = 0; i < padLen; i++) {
                        buffer[size + i] = padChar;
                    }
                   str.getChars(0, strLen, buffer, size + padLen);
               }
                size += width;
            }
            return this;
       }

       public StrBuilder bug_25_repair(Object obj, int width, char padChar) {
           if (width > 0) {
              StrBuilder.getNullText();
              ensureCapacity(size + width);
              String str = (obj == null ? StrBuilder.getNullText() : obj.toString());
               if (str == null) {
                   str = "";
               }
               int strLen = str.length();
                if (strLen >= width) {
                    str.getChars(strLen - width, strLen, buffer, size);
                } else {
                   int padLen = width - strLen;
                    for (int i = 0; i < padLen; i++) {
                        buffer[size + i] = padChar;
                    }
                   str.getChars(0, strLen, buffer, size + padLen);
               }
                size += width;
            }
            return this;
       }


       public Vector3D bug_26(final SubLine subLine,final Line line, final boolean includeEndPoints) {
        // compute the intersection on infinite line
           Vector3D v1D = line.intersection(subLine.line);


            // check location of point with respect to first sub-line
            Location loc1 = remainingRegion.checkPoint(line.toSubSpace(v1D));

           // check location of point with respect to second sub-line
             Location loc2 = subLine.remainingRegion.checkPoint(subLine.line.toSubSpace(v1D));

            if (includeEndPoints) {
                 return ((loc1 != Location.OUTSIDE) && (loc2 != Location.OUTSIDE)) ? v1D : null;
            } else {
                return ((loc1 == Location.INSIDE) && (loc2 == Location.INSIDE)) ? v1D : null;
             }
 
     }
        public Vector3D bug_26_repair(final SubLine subLine,final Line line, final boolean includeEndPoints) {
        // compute the intersection on infinite line
           Vector3D v1D = line.intersection(subLine.line);
            if (v1D == null) {
                 return null;
             }

            // check location of point with respect to first sub-line
            Location loc1 = remainingRegion.checkPoint(line.toSubSpace(v1D));

           // check location of point with respect to second sub-line
             Location loc2 = subLine.remainingRegion.checkPoint(subLine.line.toSubSpace(v1D));

            if (includeEndPoints) {
                 return ((loc1 != Location.OUTSIDE) && (loc2 != Location.OUTSIDE)) ? v1D : null;
            } else {
                return ((loc1 == Location.INSIDE) && (loc2 == Location.INSIDE)) ? v1D : null;
             }
 
     }

        public Vector2D bug_27(final SubLine subLine, final boolean includeEndPoints) {
 
        // retrieve the underlying lines
        org.apache.commons.math3.geometry.euclidean.twod.Line line1 = (org.apache.commons.math3.geometry.euclidean.twod.Line) getHyperplane();
        org.apache.commons.math3.geometry.euclidean.twod.Line line2 = (org.apache.commons.math3.geometry.euclidean.twod.Line) subLine.getHyperplane();
 
        // compute the intersection on infinite line
        Vector2D v2D = line1.intersection(line2);


        // check location of point with respect to first sub-line
         Location loc1 = getRemainingRegion().checkPoint(line1.toSubSpace(v2D));

       // check location of point with respect to second sub-line
        Location loc2 = subLine.getRemainingRegion().checkPoint(line2.toSubSpace(v2D));

        if (includeEndPoints) {
           return ((loc1 != Location.OUTSIDE) && (loc2 != Location.OUTSIDE)) ? v2D : null;
       } else {
             return ((loc1 == Location.INSIDE) && (loc2 == Location.INSIDE)) ? v2D : null;
         }
 
     }

        public Vector2D bug_27_repair(final SubLine subLine, final boolean includeEndPoints) {
 
        // retrieve the underlying lines
        org.apache.commons.math3.geometry.euclidean.twod.Line line1 = (org.apache.commons.math3.geometry.euclidean.twod.Line) getHyperplane();
        org.apache.commons.math3.geometry.euclidean.twod.Line line2 = (org.apache.commons.math3.geometry.euclidean.twod.Line) subLine.getHyperplane();
 
        // compute the intersection on infinite line
        Vector2D v2D = line1.intersection(line2);
        if (v2D == null) {
             return null;
         }

        // check location of point with respect to first sub-line
         Location loc1 = getRemainingRegion().checkPoint(line1.toSubSpace(v2D));

       // check location of point with respect to second sub-line
        Location loc2 = subLine.getRemainingRegion().checkPoint(line2.toSubSpace(v2D));

        if (includeEndPoints) {
           return ((loc1 != Location.OUTSIDE) && (loc2 != Location.OUTSIDE)) ? v2D : null;
       } else {
             return ((loc1 == Location.INSIDE) && (loc2 == Location.INSIDE)) ? v2D : null;
         }
 
     }

    public static File bug_28(Context context, boolean preferExternal) {
        File appCacheDir = null;
        if (preferExternal && MEDIA_MOUNTED
                .equals(Environment.getExternalStorageState()) && hasExternalStoragePermission(context)) {
            appCacheDir = getExternalCacheDir(context);
        }
        if (appCacheDir == null) {
            appCacheDir = context.getCacheDir();
        }
        if (appCacheDir == null) {
            String cacheDirPath = "/data/data/" + context.getPackageName() + "/cache/";
            L.w("Can't define system cache directory! '%s' will be used.", cacheDirPath);
            appCacheDir = new File(cacheDirPath);
        }
        return appCacheDir;
    }
    public static File bug_28_repair(Context context, boolean preferExternal) {
        File appCacheDir = null;
        String externalStorageState;

        try {
            externalStorageState = Environment.getExternalStorageState();
        } catch (NullPointerException e) { // (sh)it happens (Issue #660)
            externalStorageState = "";
        }
        if (preferExternal && MEDIA_MOUNTED.equals(externalStorageState) && hasExternalStoragePermission(context)) {
            appCacheDir = getExternalCacheDir(context);
        }
        if (appCacheDir == null) {
            appCacheDir = context.getCacheDir();
        }
        if (appCacheDir == null) {
            String cacheDirPath = "/data/data/" + context.getPackageName() + "/cache/";
            L.w("Can't define system cache directory! '%s' will be used.", cacheDirPath);
            appCacheDir = new File(cacheDirPath);
        }
        return appCacheDir;
    }

    protected void bug_29() {

       Intent.getLongExtra("XXX");
        
    }
    protected void bug_29_repair() {

       Intent.getStringExtra("XXX");
        
    }

    private boolean bug_30(final HttpMethod method)
     {  
        System.out.println(" ");
        AuthState authstate = method.getProxyAuthState();
        if (authstate.isPreemptive()) {
            authstate.invalidate();
        }
    }
    private boolean bug_30_repair(final HttpMethod method)
     {  
        System.out.println(" ");
        AuthState authstate = method.getProxyAuthState();
        if (authstate.isPreemptive()) {
            authstate.invalidate();
             authstate.setAuthRequested(true);
        }
    }

    public static void bug_31(String[] args) {
        String driver = "com.mysql.jdbc.Driver"; 
        String url = "jdbc:mysql://localhost:3306/GUESTBOOK?" + "useUnicode=true&characterEncoding=Big5" ; 
        String user = "caterpillar"; 
        String password = "123456"; 
        Connection conn = null; 
        Statement stmt = null; 

        try{ 
        Class.forName(driver); 
        conn = DriverManager.getConnection(URL, user, password); 
        stmt = conn.createStatement(); 
        stmt.execute("INSERT INTO message VALUES('鑹憶鏍�" + 
        "', 'caterpillar@mail.com', '鐣欒█鍚�', "+ "'2004-5-26', '鍒版涓�娓�')"); 
        ResultSet result = stmt.executeQuery("SELECT * FROM message"); 
        while(result.next()) {
        System.out.print(result.getString(1) + " "); 
        System.out.print(result.getString(2) + " "); 
        System.out.print(result.getString(3) + " "); 
        System.out.print(result.getString(4) + " "); 
        System.out.println(result.getString(5) + " "); 
        }
        }catch(ClassNotFoundException e) {                     
        System.out.println("鎵句笉鍒伴┍鍔ㄧ▼寮�"); 
        e.printStackTrace(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }finally{
        if(stmt != null) {
        try {
        stmt.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        } 
        if(conn != null) {
        try {
        conn.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        }
        }
    }
    public static void bug_31_repair(String[] args) {
        String driver = "com.mysql.jdbc.Driver"; 
        String url = "jdbc:mysql://localhost:3306/GUESTBOOK?" + "useUnicode=true&characterEncoding=Big5" ; 
        String user = "caterpillar"; 
        String password = "123456"; 
        Connection conn = null; 
        Statement stmt = null; 

        try{ 
        Class.forName(driver); 
        conn = DriverManager.getConnection(URL, user, password); 
        stmt = conn.createStatement(); 
        stmt.execute("INSERT INTO message VALUES('鑹憶鏍�" + 
        "', 'caterpillar@mail.com', '鐣欒█鍚�', "+ "'2004-5-26', '鍒版涓�娓�')"); 
        ResultSet result = stmt.executeQuery("SELECT * FROM message"); 
        while(result.next()) {
        System.out.print(result.getString(1) + " "); 
        System.out.print(result.getString(2) + " "); 
        System.out.print(result.getString(3) + " "); 
        System.out.print(result.getString(4) + " "); 
        System.out.println(result.getString(5) + " "); 
        }
        result.close();
        }catch(ClassNotFoundException e) {                     
        System.out.println("鎵句笉鍒伴┍鍔ㄧ▼寮�"); 
        e.printStackTrace(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }finally{
        if(stmt != null) {
        try {
        
        stmt.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        } 
        if(conn != null) {
        try {
        conn.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        }
        }
    }
     public static void bug_32(String[] args) {
        String driver = "com.mysql.jdbc.Driver"; 
        String url = "jdbc:mysql://localhost:3306/GUESTBOOK?" + "useUnicode=true&characterEncoding=Big5" ; 
        String user = "caterpillar"; 
        String password = "123456"; 
        Connection conn = null; 
        PreparedStatement stmt = null; 

        try{ 
        Class.forName(driver); 
        conn = DriverManager.getConnection(URL, user, password); 
        stmt = conn.createStatement(); 
        stmt.execute("INSERT INTO message VALUES('鑹憶鏍�" + 
        "', 'caterpillar@mail.com', '鐣欒█鍚�', "+ "'2004-5-26', '鍒版涓�娓�')"); 
        ResultSet result = stmt.executeQuery("SELECT * FROM message"); 
        while(result.next()) {
        System.out.print(result.getString(1) + " "); 
        System.out.print(result.getString(2) + " "); 
        System.out.print(result.getString(3) + " "); 
        System.out.print(result.getString(4) + " "); 
        System.out.println(result.getString(5) + " "); 
        }
        result.close();
        }catch(ClassNotFoundException e) {                     
        System.out.println("鎵句笉鍒伴┍鍔ㄧ▼寮�"); 
        e.printStackTrace(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }finally{
        if(stmt != null) {
        try {
        
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        } 
        if(conn != null) {
        try {
        conn.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        }
        }
    }
     public static void bug_32_repair(String[] args) {
        String driver = "com.mysql.jdbc.Driver"; 
        String url = "jdbc:mysql://localhost:3306/GUESTBOOK?" + "useUnicode=true&characterEncoding=Big5" ; 
        String user = "caterpillar"; 
        String password = "123456"; 
        Connection conn = null; 
        PreparedStatement stmt = null; 

        try{ 
        Class.forName(driver); 
        conn = DriverManager.getConnection(URL, user, password); 
        stmt = conn.createStatement(); 
        stmt.execute("INSERT INTO message VALUES('鑹憶鏍�" + 
        "', 'caterpillar@mail.com', '鐣欒█鍚�', "+ "'2004-5-26', '鍒版涓�娓�')"); 
        ResultSet result = stmt.executeQuery("SELECT * FROM message"); 
        while(result.next()) {
        System.out.print(result.getString(1) + " "); 
        System.out.print(result.getString(2) + " "); 
        System.out.print(result.getString(3) + " "); 
        System.out.print(result.getString(4) + " "); 
        System.out.println(result.getString(5) + " "); 
        }
        result.close();
        }catch(ClassNotFoundException e) {                     
        System.out.println("鎵句笉鍒伴┍鍔ㄧ▼寮�"); 
        e.printStackTrace(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }finally{
        if(stmt != null) {
        try {
        
        stmt.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        } 
        if(conn != null) {
        try {
        conn.close(); 
        }catch(SQLException e) {
        e.printStackTrace(); 
        }
        }
        }
    }

    public JSType bug_33(JSType that) {
        UnionType.Builder builder = new UnionType().builder(registry);
        for (JSType alternate : alternates) {
          if (alternate.isSubtype(that)) {
            builder.addAlternate(alternate);
          }
        }
        if (that instanceof UnionType) {
          for (JSType otherAlternate : ((UnionType) that).alternates) {
            if (otherAlternate.isSubtype(this)) {
              builder.addAlternate(otherAlternate);
            }
          }
        } else if (that.isSubtype(this)) {
          builder.addAlternate(that);
        }
        JSType result = builder.build();
        if (result != null) {
          return result;
        }
    }
    public JSType bug_33_repair(JSType that) {
        UnionType.Builder builder = new UnionType().builder(registry);
        for (JSType alternate : alternates) {
          if (alternate.isSubtype(that)) {
            builder.addAlternate(alternate);
          }
        }
        if (that instanceof UnionType) {
          for (JSType otherAlternate : ((UnionType) that).alternates) {
            if (otherAlternate.isSubtype(this)) {
              builder.addAlternate(otherAlternate);
            }
          }
        } else if (that.isSubtype(this)) {
          builder.addAlternate(that);
        }
        JSType result = builder.build();
        if (!result.isNoType()) {
          return result;
        }
    }
    public int bug_34(Parameters params) throws CmdLineException {
        String param = null;
        String param = params.getParameter(0);
        if (param == null) {
          setter.addValue(true);
          return 0;
        } else {
          String lowerParam = param.toLowerCase();
          if (TRUES.contains(lowerParam)) {
            setter.addValue(true);
          } else if (FALSES.contains(lowerParam)) {
            setter.addValue(false);
          } else {
            setter.addValue(true);
            return 0;
          }
          return 1;
        }
    }

    public int bug_34_repair(Parameters params) throws CmdLineException {
        String param = null;
        try {
          param = params.getParameter(0);
        } catch (CmdLineException e) {}

        if (param == null) {
          setter.addValue(true);
          return 0;
        } else {
          String lowerParam = param.toLowerCase();
          if (TRUES.contains(lowerParam)) {
            setter.addValue(true);
          } else if (FALSES.contains(lowerParam)) {
            setter.addValue(false);
          } else {
            setter.addValue(true);
            return 0;
          }
          return 1;
        }
    }

    private void bug_35(NodeTraversal t, Node n,
          String functionName, HashMap<String, ObjectType> properties,
          HashMap<String, ObjectType> currentProperties,
          ObjectType interfaceType) {
        Set<String> currentPropertyNames =
            interfaceType.getImplicitPrototype().getOwnPropertyNames();
    }
    private void bug_35_repair(NodeTraversal t, Node n,
          String functionName, HashMap<String, ObjectType> properties,
          HashMap<String, ObjectType> currentProperties,
          ObjectType interfaceType) {

        ObjectType implicitProto = interfaceType.getImplicitPrototype();
        Set<String> currentPropertyNames;
        if (implicitProto == null) {
          // This can be the case if interfaceType is proxy to a non-existent
          // object (which is a bad type annotation, but shouldn't crash).
          currentPropertyNames = ImmutableSet.of();
        } else {
          currentPropertyNames = implicitProto.getOwnPropertyNames();
        }
    }

    private void bug_36(Iterator<CharSequence> partsIterator,
                                               Node argListNode)
    {

        CharSequence part = partsIterator.next();
    }

    private void bug_36_repair(Iterator<CharSequence> partsIterator,
                                               Node argListNode)
    {
        if (!partsIterator.hasNext()) {
          return IR.string("");
        }

        CharSequence part = partsIterator.next();
    }

    private void bug_37()
    {

        Log.warn("xxx");
    }
    private void bug_37_repair(Log log)
    {

        if (log.isWarnEnable()){
            log.warn("xxx");       
        }
        
    }

    private void bug_38(StringTokenizer s)
    {

        s.nextToken();
    }
    private void bug_38_repair(StringTokenizer s)
    {

        if(s.hasMoreTokens())
        {
             s.nextToken();
        }
    }

    private void bug_39(Class exceptionClass)
    {

        HashMap codeMap = new HashMap();
        codeMap.put(RepositoryException.class, new Integer(DavServletResponse.SC_FORBIDDEN));
        ((Integer)(codeMap.get(exceptionClass))).intValue();
    }
    private void bug_39_repair(Class exceptionClass)
    {

        HashMap codeMap = new HashMap();
        codeMap.put(RepositoryException.class, new Integer(DavServletResponse.SC_FORBIDDEN));
        Integer code = (Integer) codeMap.get(exceptionClass);
        if (code == null) {

        }
        else{
            code.intValue();
        }
    }
    private void bug_40(IOManager ioManager)
    {

        
         return ioManager.getDetector().detect(null, metadata).toString();
    }

    private void bug_40_repair(IOManager ioManager)
    {

        if (ioManager != null && ioManager.getDetector() != null) {
                return ioManager.getDetector().detect(null, metadata).toString();
           } else {
                return "application/octet-stream";
           }
    }

    private void bug_41(NodeState  context, ItemStateManager ism)
    {
        NodeState next =(NodeState) ism.getItemState(context.getParentId());
    }

    private void bug_41_repair(NodeState  context, ItemStateManager ism)
    {
        NodeState next = context.getParentId() == null ? null :(NodeState) ism.getItemState(context.getParentId());
    }
    
    public HierarchyEntry getHierarchyEntry() { //用这个函数，其实是在bug_42中调用，说明我们的程序支持当前分析文件中的函数定义类型的分析。
            HierarchyEntry hierarchyEntry=new HierarchyEntry();
            return hierarchyEntry;
    }


    public NodeState bug_42() throws ItemNotFoundException, RepositoryException {
       
        return getHierarchyEntry().getParent().getNodeState();
       
    }    
    public NodeState bug_42_repair() throws ItemNotFoundException, RepositoryException {
       NodeEntry parent = getHierarchyEntry().getParent();
        if (parent != null) {
            return getHierarchyEntry().getParent().getNodeState();
        }
        return null;
    }

    public void bug_43(Map<String, String> parameters){
        String configFile = parameters.get(JCAManagedConnectionFactory.CONFIGFILE_KEY);
        String homeDir="C:\\";
        RepositoryConfig.create(configFile, homeDir);
    }
    public void bug_43_repair(Map<String, String> parameters){
        String configFile = parameters.get(JCAManagedConnectionFactory.CONFIGFILE_KEY);
        String homeDir="C:\\";
        if (configFile != null) {
            RepositoryConfig.create(configFile, homeDir);
        }
    }


    public void bug_44(FileSystemResource nodeFile){
       nodeFile.delete();
    }
    public void bug_44_repair(FileSystemResource nodeFile){
        if (nodeFile.exists()) nodeFile.delete();
    }


    public void bug_45(PlotRenderingInfo plotState){
        EntityCollection entities = plotState.getOwner().getEntityCollection();
    }
    public void bug_45_repair(PlotRenderingInfo plotState){
        ChartRenderingInfo owner = plotState.getOwner();
        if (owner != null) {
              EntityCollection entities = owner.getEntityCollection();
        }
    }
    public void bug_46(StatisticalCategoryDataset dataset,int row,int column){
        Number meanValue = dataset.getMeanValue(row, column);
    }
    public void bug_46_repair6(StatisticalCategoryDataset dataset,int row,int column){
        Number meanValue = dataset.getMeanValue(row, column);
        if (meanValue == null) {
            return;
        }
    }

    public void bug_47(StatisticalCategoryDataset dataset,int row,int column){
        double valueDelta = dataset.getStdDevValue(row, column).doubleValue();
    }
    public void bug_47_repair6(StatisticalCategoryDataset dataset,int row,int column){
        Number n = dataset.getStdDevValue(row, column);
        if (n != null) {
            double valueDelta = n.doubleValue();
        }   
    }


    public void bug_48(XYDataset d){
        XYItemRenderer r = XYPlot.getRendererForDataset(d);

    }
    public void bug_48_repair6(StatisticalCategoryDataset dataset,int row,int column){
        XYItemRenderer r = XYPlot.getRendererForDataset(d);
        if (r != null) {
            
        }   
    }

    public void bug_49(CategoryPlot plot,int index){
        CategoryDataset dataset =plot.getDataset(index);
    }
    public void bug_49_repair(CategoryPlot plot,int index){
        CategoryDataset dataset =plot.getDataset(index);
        if (dataset != null) {
        }  
    }

    public void bug_50(Map backgroundRangeMarkers,int index){
        ArrayList makers=(ArrayList) backgroundRangeMarkers.get(new Integer(index));
    }
    public void bug_50_repair(Map backgroundRangeMarkers,int index){
        ArrayList makers=(ArrayList) backgroundRangeMarkers.get(new Integer(index));
        if (makers != null) {
        }  
    }
    public void bug_51(File path){
        RandomAccessFile file = new RandomAccessFile(path, "rw");
    }
        
    public void bug_51_repair(File path){
        RandomAccessFile file = new RandomAccessFile(path, "rw");
        file.close();
    }
    public File bug_52(File lockDir,StringBuffer buf){
        File lockFile = new File(lockDir, buf.toString());
        return lockFile.createNewFile();
    }
    public File bug_52_repair(File lockDir,StringBuffer buf){
        File lockFile = new File(lockDir, buf.toString());
        if (!lockDir.exists()) {
            if (!lockDir.mkdirs()) {
            throw new IOException("Cannot create lock directory: " + lockDir);
           }
        }
        return lockFile.createNewFile();
    }

    public int bug_53(IndexReader r){
       Bits delDocs = MultiFields.getDeletedDocs(r);
    }
    public int bug_53_repair(IndexReader r){
       Bits delDocs = MultiFields.getDeletedDocs(r);
        if (delDocs != null) {
        } 
    }
    
    public void bug_54 (final Context context, final Intent intent) {
        final IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        final Intent batteryStatus = context.registerReceiver(null, ifilter);
    }

    public void bug_54_repair (final Context context, final Intent intent) {
        final IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        final Intent batteryStatus = context.getApplicationContext().registerReceiver(null, ifilter);
    }



    private boolean bug_55(ItemData data, Path path) throws AccessDeniedException, RepositoryException {
        if (data.getState().getStatus() == ItemState.STATUS_NEW &&!data.getDefinition().isProtected()) {
            // NEW items can always be read as long they have been added
             // through the API and NOT by the system (i.e. protected props).
             return true;
         } else {
            
         }

     }

    private boolean bug_55_repair(ItemData data, Path path) throws AccessDeniedException, RepositoryException {
                    // JCR-1601: cached item may just have been invalidated
         ItemState state = data.getState();
         if (state == null) {
             throw new InvalidItemStateException(data.getId() + ": the item does not exist anymore");
        }
        if (state.getStatus() == ItemState.STATUS_NEW &&
                 !data.getDefinition().isProtected()) {
            // NEW items can always be read as long they have been added
             // through the API and NOT by the system (i.e. protected props).
             return true;
         } else {
         }
    }
    public void bug_56 () {
        JFrame.setVisible(true);
        JFrame.pack();
    }
    public void bug_56_repair() {
        JFrame.pack();
        JFrame.setVisible(true);
    }

    public void bug_57 () {
        FileChannel fileOut = new FileOutputStream(file).getChannel();
        fileOut.write(ByteBuffer.wrap("Whatever you want to write".getBytes()));
    }
    public void bug_57_repair() {
        FileChannel fileOut = new FileOutputStream(file).getChannel();
        fileOut.write(ByteBuffer.wrap("Whatever you want to write".getBytes()));
        fileOut.close();
    }

    public void bug_58 () {
        short[] payload = {1,2,3,4,5,6,7,8,9,0};
        ByteBuffer myByteBuffer = ByteBuffer.allocate(20);
        myByteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        ShortBuffer myShortBuffer = myByteBuffer.asShortBuffer();
        myShortBuffer.put(payload);

        FileChannel out = new FileOutputStream("sample.bin").getChannel();
        out.write(myByteBuffer);
        out.close();
    }

    public void bug_58_repair () {
        try{
            short[] payload = {1,2,3,4,5,6,7,8,9,0};
            ByteBuffer myByteBuffer = ByteBuffer.allocate(20);
            myByteBuffer.order(ByteOrder.LITTLE_ENDIAN);

            ShortBuffer myShortBuffer = myByteBuffer.asShortBuffer();
            myShortBuffer.put(payload);

            FileChannel out = new FileOutputStream("sample.bin").getChannel();
            out.write(myByteBuffer);
            out.close();
        } catch(Exception e){

        }
    }
    public void bug_59(String id) {
        ArrayList<UserInfo> listUserInfo = new ArrayList<UserInfo>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME, new String[]{COLUMN_APP_ID}, COLUMN_APP_ID + "=?", new String[]{id + ""}, null, null, null);

        if (cursor != null) {
            while (cursor.moveToNext()) {
              UserInfo userInfo = new UserInfo();
              userInfo.setAppId(cursor.getString(cursor.getColumnIndex(COLUMN_APP_ID)));
              // HERE YOU CAN MULTIPLE RECORD AND ADD TO LIST 
              listUserInfo.add(userInfo);
            }
        }

        cursor.close();
        return listUserInfo;
    }
    public void bug_59_repair(String id) {
        ArrayList<UserInfo> listUserInfo = new ArrayList<UserInfo>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME, new String[]{COLUMN_APP_ID}, COLUMN_APP_ID + "=?", new String[]{id + ""}, null, null, null);

        if (cursor != null) {
            while (cursor.moveToNext()) {
              UserInfo userInfo = new UserInfo();
              userInfo.setAppId(cursor.getString(cursor.getColumnIndex(COLUMN_APP_ID)));
              // HERE YOU CAN MULTIPLE RECORD AND ADD TO LIST 
              listUserInfo.add(userInfo);
            }
        }
        cursor.close();
        db.close();
        return listUserInfo;
    }

    public void bug_60(String id) {
        String text = "<img src=\"mysrc\" width=\"128\" height=\"92\" border=\"0\" alt=\"alt\" /><p><strong>";

        text = text.substring(text.indexOf("src=\""));
        text = text.substring("src=\"".length());
        text = text.substring(0, text.indexOf("\""));
        System.out.println(text);
    }

    public void bug_60_repair(String id) {
        try{
            String text = "<img src=\"mysrc\" width=\"128\" height=\"92\" border=\"0\" alt=\"alt\" /><p><strong>";

            text = text.substring(text.indexOf("src=\""));
            text = text.substring("src=\"".length());
            text = text.substring(0, text.indexOf("\""));
            System.out.println(text);    
        }catch(Exception e)
        {

        }
    }

    public void bug_61() {
            for (int i = 0; i < maxId; i++) {

            double tmp = Integer.parseInt("123");
            sum = sum + tmp;
            cursor.moveToNext();
            }
    }
    public void bug_61_repair() {
        try{
            for (int i = 0; i < maxId; i++) {

            double tmp = Integer.parseInt("123");
            sum = sum + tmp;
            cursor.moveToNext();
            }
        }catch(Exception e)
        {

        }
    }

    private void bug_62(Context ctx, AttributeSet attrs) {
        TypedArray a = ctx.obtainStyledAttributes(attrs, R.styleable.TextViewPlus);
        String customFont = a.getString(R.styleable.TextViewPlus_customFont);
        setCustomFont(ctx, customFont);
        a.recycle();
    }

    private void bug_62_repair(Context ctx, AttributeSet attrs) {
        TypedArray a = ctx.obtainStyledAttributes(attrs, R.styleable.TextViewPlus);
        String customFont = a.getString(R.styleable.TextViewPlus_customFont);
        if (customFont!=null){
            setCustomFont(ctx, customFont);
            a.recycle();    
        }
    }

    public void bug_63() throws IOException {
        TreeMap fieldToReader = new TreeMap();
        field = (String)fieldToReader.firstKey();
        if (field != null)
            termEnum = ((IndexReader)fieldToReader.get(field)).terms();
    }
    public void bug_63_repair() throws IOException {
        TreeMap fieldToReader = new TreeMap();
        try{
                field = (String)fieldToReader.firstKey();    
        }catch(NoSuchElementException e) {
            return;
        }
        
        if (field != null)
            termEnum = ((IndexReader)fieldToReader.get(field)).terms();
    }

    public void bug_64() {
        
        SimpleDateFormat formater = new SimpleDateFormat("yyyy-MM-dd hh:mm");
        
    }
    public void bug_64_repair() {
        try{
            SimpleDateFormat formater = new SimpleDateFormat("yyyy-MM-dd hh:mm");
        }catch(Exception e){

        }
    }


    public void bug_65(String date_input) {
        
        String parts[] = date_input.split("-");
        
    }
    public void bug_65_repair(String date_input) {
        if(date_input!=null){
            String parts[] = date_input.split("-");
        }
    }


    public void bug_66(File file) {
        
        FileInputStream input = new FileInputStream(file);
        
    }
    public void bug_66_repair(File file) {
        try{
            FileInputStream input = new FileInputStream(file);
        }catch(Exception e){

        }
    }
    

    public void bug_67() {
        Process p = Runtime.getRuntime().exec("echo \"hello\"");
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        System.out.println(br.readLine());
    }
    public void bug_67_repair() {
        Process p = Runtime.getRuntime().exec("echo \"hello\"");
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        System.out.println(br.readLine());
    }
    public void bug_68( Bundle bundle ) {
        String image_url =bundle.getString("imageUrl");
    }
    public void bug_68_repair( Bundle bundle) {
        String image_url =bundle.getString("imageUrl");
        if(image_url!=null){
            String parts[] = date_input.split("-");
        }
    }

    public void bug_69( Bundle bundle ) {
        String image_url =bundle.getString("imageUrl");
    }
    public void bug_69_repair( Bundle bundle) {
        try{
        String image_url =bundle.getString("imageUrl");    
        }catch(Exception e){

        }
    }
    public void bug_70() {
        Class interface1 = Class.ForName("a.b.c.d.IMyInterface");
    }
    public void bug_70_repair() {
        try{
            Class interface1 = Class.ForName("a.b.c.d.IMyInterface");  
        }catch(Exception e){
        }
    }

    public void bug_71(String str) {
        String first = st.nextToken();
        double ff = Double.parseDouble(first);
    }
    public void bug_71_repair(String str) {
        try{
            String first = st.nextToken();
            double ff = Double.parseDouble(first); 
        }catch(Exception e){
        }
        
    }
    public void bug_72(String str) {
        StringBuilder builder = new StringBuilder(); 
        
        // Set up HTTP post 
        // HttpClient is more then less deprecated. Need to change to URLConnection 
        HttpClient client = new DefaultHttpClient( ); 
        HttpGet httpGet = new HttpGet(params[0]); 
        HttpResponse response = client.execute(httpGet);
        StatusLine statusLine = response.getStatusLine();
        int statusCode = statusLine.getStatusCode();
   }
   public void bug_72_repair(String str) {
        try{
        StringBuilder builder = new StringBuilder(); 
        
        // Set up HTTP post 
        // HttpClient is more then less deprecated. Need to change to URLConnection 
        HttpClient client = new DefaultHttpClient( ); 
        HttpGet httpGet = new HttpGet(params[0]); 
        HttpResponse response = client.execute(httpGet);
        StatusLine statusLine = response.getStatusLine();
        int statusCode = statusLine.getStatusCode();
        }catch(Exception e){
        }
   }
    public void bug_73(String str) {
        HttpClient client = new DefaultHttpClient( ); 
        HttpResponse response2 = httpclient.execute(httpPost);
        System.out.println(response2.getStatusLine());
        HttpEntity entity2 = response2.getEntity();
        // do something useful with the response body
        // and ensure it is fully consumed

        String response = new Scanner(entity2.getContent()).useDelimiter("\\A").next();
        System.out.println(response);
   }
    public void bug_73_repair(String str) {
        try{
        HttpClient client = new DefaultHttpClient( ); 
        HttpResponse response2 = httpclient.execute(httpPost);
        System.out.println(response2.getStatusLine());
        HttpEntity entity2 = response2.getEntity();
        // do something useful with the response body
        // and ensure it is fully consumed

        String response = new Scanner(entity2.getContent()).useDelimiter("\\A").next();
        System.out.println(response);
        }catch(Exception e){
        }
   }
    public void bug_74() {
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        HttpServletRequest httpServletRequest = (HttpServletRequest) (externalContext.getRequestMap().get("com.liferay.portal.kernel.servlet.PortletServletRequest"));
        PortletRequest portletRequest = (PortletRequest) httpServletRequest.getAttribute("javax.portlet.request");

        String packageId = null;
        HttpServletRequest httpRequest = null;
        if(portletRequest != null){
            httpRequest = PortalUtil.getOriginalServletRequest(PortalUtil.getHttpServletRequest(portletRequest));
            packageId = httpRequest.getParameter("packageId");
        }
    }
    public void bug_74_repair() {
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        HttpServletRequest httpServletRequest = (HttpServletRequest) (externalContext.getRequestMap().get("com.liferay.portal.kernel.servlet.PortletServletRequest"));
        PortletRequest portletRequest = (PortletRequest) httpServletRequest.getAttribute("javax.portlet.request");

        String packageId = null;
        HttpServletRequest httpRequest = null;
        if(portletRequest != null){
            httpRequest = PortalUtil.getOriginalServletRequest(PortalUtil.getHttpServletRequest(portletRequest));
            packageId = httpRequest.getParameter("packageId");
            if(packageId!=null){

            }
        }
    }

    public void bug_75() {
        Intent intent = getIntent();
        if (intent != null)
        {
            String clicked = intent.getStringExtra("button");
        }
    }
    public void bug_75_repair() {
        Intent intent = getIntent();
        if (intent != null)
        {
            String clicked = intent.getStringExtra("button");
            if (clicked!=null) {
                
            }
        }
    }

    public void bug_76() {
        JButton b = new Button("Click me");
        b.addActionListener(this);
    }
    public void bug_76_repair() {
        JButton b = new JButton("Click me");
        b.addActionListener(this);
    }

    public void bug_77(){
        JSONArray jArray = json.getJSONArray("pages");
        for (int i = 0; i < jArray.length(); i++) {
            JSONObject jsonMasteryPage = jArray.getJSONObject(i);
            long id = jsonMasteryPage.getLong("id");
            String name = jsonMasteryPage.getString("name");
        }
    }
    public void bug_77_repair(){
        try{
        JSONArray jArray = json.getJSONArray("pages");
        for (int i = 0; i < jArray.length(); i++) {
            JSONObject jsonMasteryPage = jArray.getJSONObject(i);
            long id = jsonMasteryPage.getLong("id");
            String name = jsonMasteryPage.getString("name");
        }
        }catch(Exception e){
        }
    }

    public void bug_78(){
            Document doc = Jsoup.connect("http://en.wikipedia.org/wiki/Main_Page");
            Elements el = doc.select("div.mp-tfa");
            System.out.println(el);
    }
    public void bug_78_repair(){
        try{
            Document doc = Jsoup.connect("http://en.wikipedia.org/wiki/Main_Page");
            Elements el = doc.select("div.mp-tfa");
            System.out.println(el);
         }catch(Exception e){
        }
    }
    public void bug_79(){
        KeyStore keyStore = KeyStore.getInstance("PKCS11",sunpkcs11);
        keyStore.load(null, pin.toCharArray());
    }
    public void bug_79_repair(){
        try{
        KeyStore keyStore = KeyStore.getInstance("PKCS11",sunpkcs11);
        keyStore.load(null, pin.toCharArray());
        }catch(Exception e){
        }
    }
    public void bug_80(ProgressDialog processingDialog){
        
            
        processingDialog.dismiss();
        
        
    }
    public void bug_80_repair(ProgressDialog processingDialog){
        if(processingDialog!=null){

        processingDialog.dismiss();
        }
        
    }

    public void bug_81(){

         Random randomNumber = new Random ();
        System.out.println(randomNumber.nextInt(53));

    }

    public void bug_81_repair(){
        try{
         Random randomNumber = new Random ();
        System.out.println(randomNumber.nextInt(53));
        }catch(Exception e){
        }
    }
   
    public void bug_82(){
        connection =  DriverManager.getConnection(connURL,userName,password);
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("select * from employee em left join department dept em.deptid=dept.id");
        while (rs.next()) {
            rs.getString(i123);
        }
    }

    public void bug_82_repair(){
        connection =  DriverManager.getConnection(connURL,userName,password);
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("select * from employee em left join department dept em.deptid=dept.id");
        while (rs.next()) {
            try{
                rs.getString(i123);
            }catch(Exception e){
            }
        }   
    }  
    public void bug_83(){
        Scanner scanner = new Scanner(inputStream);
        int counter = 5;
        while (scanner.hasNext()) {
               String line = scanner.nextLine();
               String[] array;
               if(counter>=0)   
               {
                   array = line.split(";");
                   System.out.println(line);
                   counter--;
               }
         }
    }
    public void bug_83_repair(){
        Scanner scanner = new Scanner(inputStream);
        int counter = 5;
        while (scanner.hasNextLine()) {
               String line = scanner.nextLine();
               String[] array;
               if(counter>=0)   
               {
                   array = line.split(";");
                   System.out.println(line);
                   counter--;
               }
         }
    }
    public void bug_84(){
        Arraylist<Socket> sockets=Server.getSockets();
        for(Socket current: sockets)
        {
           ObjectOutputStream out=new ObjectOutputStream (current.getOutputStream());
           out.flush();
           out.writeObject(object);
           out.flush();
           out.close();
         }
    }

    public void bug_84_repair(){
        Arraylist<Socket> sockets=Server.getSockets();
        try{
            for(Socket current: sockets)
            {
               ObjectOutputStream out=new ObjectOutputStream (current.getOutputStream());
               out.flush();
               out.writeObject(object);
               out.flush();
               out.close();
             }
        }catch(Exception e){
            }

    }
    public void bug_85(String s){
        String nodeName = s.charAt(0) + "";
    }
    public void bug_85_repair(String s){
        try{
            String nodeName = s.charAt(0) + "";    
        }catch(Exception e){
            }
        
    }
    
    public void bug_86(String s){
        String[] split = s.split(" ");
    }
    public void bug_86_repair(String s){
        if(s!=null){
            String[] split = s.split(" ");    
        }
        
    }
    
    public void bug_87(){
        Thread.sleep();
    }
    public void bug_87_repair(){
        try{
           Thread.sleep() ;
         }catch(Exception e){
            }
        
    }
    public void bug_88(){
        URL url = new URL(someStringUrl);
        HttpUrlConnection con = (HttpUrlConnection) url.openConnection();
        // do some stuff with con, add headers, add request body, etc.
        con.getInputStream();
    }
    public void bug_88_repair(){
        try{
            URL url = new URL(someStringUrl);
            HttpUrlConnection con = (HttpUrlConnection) url.openConnection();
            // do some stuff with con, add headers, add request body, etc.
            con.getInputStream();
                 }catch(Exception e){
            }
    }

    public void bug_89(){
            GetMethod getMethod = new GetMethod(API_URL + "rest/annotate/?" +
                "confidence=" + CONFIDENCE
                + "&support=" + SUPPORT
                + "&text=" + URLEncoder.encode(text.text(), "utf-8"));
            getMethod.addRequestHeader(new Header("Accept", "application/json"));
            spotlightResponse = request(getMethod);
    }
    public void bug_89_repair(){
        try{
            GetMethod getMethod = new GetMethod(API_URL + "rest/annotate/?" +
                "confidence=" + CONFIDENCE
                + "&support=" + SUPPORT
                + "&text=" + URLEncoder.encode(text.text(), "utf-8"));
            getMethod.addRequestHeader(new Header("Accept", "application/json"));
            spotlightResponse = request(getMethod);
           }catch(Exception e){
            }
    }

    public void bug_90(){
        Configuration configuration = new Configuration();
        configuration.set("dictionary", args[2]);

        Job job = Job.getInstance(configuration);
        job.setJarByClass(SentimentAnalysis.class);
        job.setMapperClass(SentimentSplit.class);
        job.setReducerClass(SentimentCollection.class);
        job.setOutputKeyClass(Text.class);
        job.setOutputValueClass(IntWritable.class);
        FileInputFormat.addInputPath(job, new Path(args[0]));
        FileOutputFormat.setOutputPath(job, new Path(args[1]));

        job.waitForCompletion(true);
    }


    public void bug_90_repair(){
        try{
        Configuration configuration = new Configuration();
        configuration.set("dictionary", args[2]);

        Job job = Job.getInstance(configuration);
        job.setJarByClass(SentimentAnalysis.class);
        job.setMapperClass(SentimentSplit.class);
        job.setReducerClass(SentimentCollection.class);
        job.setOutputKeyClass(Text.class);
        job.setOutputValueClass(IntWritable.class);
        FileInputFormat.addInputPath(job, new Path(args[0]));
        FileOutputFormat.setOutputPath(job, new Path(args[1]));

        job.waitForCompletion(true);
          }catch(Exception e){
            }
    }
    public void bug_91(){
        if(Log.isDebugEnabled()){
            Log.info("yayayayay");
        }
    }
    public void bug_91_repair(){
        if(Log.isDebugEnabled()){
            Log.debug("yayayayay");
        }
    }

    public void bug_92(){
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {

            final byte[] iv = new byte[IV_LENGTH];
            buffer.get(iv);

            final byte[] content = new byte[buffer.remaining()];
            buffer.get(content);

            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            synchronized (decryptionCipher) {
                decryptionCipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
                return decryptionCipher.doFinal(content);
            }

        } catch (final BufferUnderflowException | InvalidAlgorithmParameterException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e) {
            return null;
        }
    }


    public void bug_92_repair(){
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {

            
            

            final byte[] content = new byte[buffer.remaining()];
            buffer.get(content);
            
            SecureRandom random = SecureRandom();
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(random);

            synchronized (decryptionCipher) {
                decryptionCipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
                return decryptionCipher.doFinal(content);
            }

        } catch (final BufferUnderflowException | InvalidAlgorithmParameterException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e) {
            return null;
        }
    }


    public static String bug_93(String property) throws GeneralSecurityException, UnsupportedEncodingException {

        byte[] SALT = {
            (byte) 0xde, (byte) 0x33, (byte) 0x10, (byte) 0x12,
            (byte) 0xde, (byte) 0x33, (byte) 0x10, (byte) 0x12,
        };
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(habridgeKey));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(SALT, 20));
        return base64Encode(pbeCipher.doFinal(property.getBytes("UTF-8")));
    }


    public static String bug_93_repair(String property) throws GeneralSecurityException, UnsupportedEncodingException {

        SecureRandom salt = new SecureRandom();
        byte bytes[] = new byte[100];
        salt.nextBytes(bytes);

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(habridgeKey));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(bytes, 20));
        return base64Encode(pbeCipher.doFinal(property.getBytes("UTF-8")));
    }

    public static String bug_94(String property,char[] habridgeKey) throws GeneralSecurityException, UnsupportedEncodingException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(habridgeKey));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(SALT, 20));
        return base64Encode(pbeCipher.doFinal(property.getBytes("UTF-8")));
    }

    public void bug_94_repair(char[] password,byte[] salt,int iterationCount,int keylength ) {
        PBEKeySpec pbeks = new PBEKeySpec(password, salt, iterationCount, keylength);
    }

    public static String bug_95(String key, String string) {
        SecretKeySpec object = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init((Key) object);
            byte[] byteArray = mac.doFinal(string.getBytes("UTF-8"));
            return new String(new Hex().encode(byteArray), "ISO-8859-1");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String bug_95_repair(String key, String string) {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_128");
        PBEKeySpec pbeks = new PBEKeySpec(password, salt, iterationCount, keylength);
        SecretKey key =  skf.generateSecret(pbeks);
        byte keyMaterial[] = key.getEncoded();
        SecretKeySpec sks = new SecretKeySpec(keyMaterial, algorithm);
    }

    public static String bug_96(String key,String data) {
        if(data == null)
            return null;
        try{
            DESKeySpec dks = new DESKeySpec(key.getBytes());            
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            //key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(IV_PARAMS_BYTES);;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,paramSpec);           
            byte[] bytes = cipher.doFinal(data.getBytes());            
            return byte2hex(bytes);
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    public static String bug_96_repair(String key,String data) {
            
        Cipher c = Cipher.getInstance("PBEWithHmacSHA224AndAES_128");
        SecureRandom random = new SecureRandom();
        c.init(Cipher.ENCRYPT_MODE, key, random);   
    }
    public static void bug_97(String[] args) throws IOException
    {
        BufferedReader bufr = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(System.out);
        String line = null;
        while ((line = bufr.readLine())!=null)
        {
            if ("over".equals(line))
                break;
            out.println(line.toUpperCase());
            out.flush();
        }
        bufr.close();
    }
    
    public static void bug_97_repair(String[] args) throws IOException
    {
        BufferedReader bufr = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(System.out);
        String line = null;
        while ((line = bufr.readLine())!=null)
        {
            if ("over".equals(line))
                break;
            out.println(line.toUpperCase());
            out.flush();
        }
        out.close();
        bufr.close();
    }
    public static void bug_98(String[] args) throws IOException {
        
        FileInputStream  fis = new FileInputStream("abc.txt"); 
        
        int x = fis.read();
        System.out.println(x);
 
    }
    public static void bug_98_repair(String[] args) throws IOException {
        if(File.exists("abc.txt")){
            FileInputStream  fis = new FileInputStream("abc.txt"); 
        
        int x = fis.read();
        System.out.println(x);    
        }
    }
    public static void bug_99(Set set){
        Iterator<Integer> it = set.iterator();

        

        System.out.println(it.next());
    }

    public static void bug_99_repair(Set set){
        Iterator<Integer> it = set.iterator();

        while(it.hasNext()){

        System.out.println(it.next());

        }
    }

    public static String bug_100(byte[] keyBytes, String plainText)
            throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedString = Base64.byteArrayToBase64(encryptedBytes);

        return encryptedString;
    }

    public static String bug_100_repair(byte[] keyBytes, String plainText)
            throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedString = Base64.byteArrayToBase64(encryptedBytes);

        return encryptedString;
    }

    public static Node bug_101(IRFactory nf) throws Exception {

        Node pn = nf.initFunction(fnNode, functionIndex, body, syntheticType);
        if (memberExprNode != null) {
            pn = nf.initFunction(fnNode, functionIndex, body, syntheticType);
            pn = nf.createAssignment(Token.ASSIGN, memberExprNode, pn);
            if (functionType != FunctionNode.FUNCTION_EXPRESSION) {
                // XXX check JScript behavior: should it be createExprStatement?
                pn = nf.createExprStatementNoReturn(pn, baseLineno);
            }
        }
        return pn;
    }
    public static Node bug_101_repair(IRFactory nf) throws Exception {
        
        Node pn = nf.initFunction(fnNode, functionIndex, body, syntheticType);
        if (memberExprNode != null) {

            pn = nf.createAssignment(Token.ASSIGN, memberExprNode, pn);
            if (functionType != FunctionNode.FUNCTION_EXPRESSION) {
                // XXX check JScript behavior: should it be createExprStatement?
                pn = nf.createExprStatementNoReturn(pn, baseLineno);
            }
        }
        return pn;
    }


}
