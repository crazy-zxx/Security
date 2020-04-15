package com.me.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Test {

    public static void main(String[] args) throws Exception {

        //URL编码是编码算法，不是加密算法。URL编码的目的是把任意文本数据编码为%前缀表示的文本，编
        // 码后的文本仅包含A~Z，a~z，0~9，-，_，.，*和%，便于浏览器和服务器处理。
        //URL编码有一套规则：
        //  如果字符是A~Z，a~z，0~9以及-、_、.、*，则保持不变；
        //  如果是其他字符，先转换为UTF-8编码，然后对每个字节以%XX表示
        //URL编码总是大写
        //Java标准库提供了一个URLEncoder类来对任意字符串进行URL编码
        //和标准的URL编码稍有不同，URLEncoder把空格字符编码成+，而现在的URL编码标准要求空格被编码为%20，
        // 不过，服务器都可以处理这两种情况。
        String encoded = URLEncoder.encode("中文!", StandardCharsets.UTF_8);
        System.out.println(encoded);

        //Java标准库的URLDecoder就可以解码
        String decoded = URLDecoder.decode("%E4%B8%AD%E6%96%87%21", StandardCharsets.UTF_8);
        System.out.println(decoded);


        //Base64编码是对二进制数据进行编码，表示成文本格式。
        //Base64编码的缺点是传输效率会降低，因为它把原始数据的长度增加了1/3。
        //和URL编码一样，Base64编码是一种编码算法，不是加密算法。
        //Base64编码可以把任意长度的二进制数据变为纯文本，且只包含A~Z、a~z、0~9、+、/、=这些字符。
        // 它的原理是把3字节的二进制数据按6bit一组，用4个int整数表示，然后查表，把int整数用索引对应到字符，得到编码后的字符串。
        //字符A~Z对应索引0~25，字符a~z对应索引26~51，字符0~9对应索引52~61，最后两个索引62、63分别用字符+和/表示。

        //在Java中，二进制数据就是byte[]数组。Java标准库提供了Base64来对byte[]数组进行编解码
        byte[] input = new byte[]{(byte) 0xe4, (byte) 0xb8, (byte) 0xad};
        String b64encoded = Base64.getEncoder().encodeToString(input);
        System.out.println(b64encoded);

        //要对Base64解码，仍然用Base64这个类
        byte[] output = Base64.getDecoder().decode("5Lit");
        System.out.println(Arrays.toString(output)); // [-28, -72, -83]

        //如果输入的byte[]数组长度不是3的整数倍肿么办？
        // 这种情况下，需要对输入的末尾补一个或两个0x00，
        // 编码后，在结尾加一个=表示补充了1个0x00，加两个=表示补充了2个0x00，解
        // 码的时候，去掉末尾补充的一个或两个0x00即可。
        //实际上，因为编码后的长度加上=总是4的倍数，所以即使不加=也可以计算出原始输入的byte[]。
        // Base64编码的时候可以用withoutPadding()去掉=，解码出来的结果是一样的：
        byte[] input1 = new byte[]{(byte) 0xe4, (byte) 0xb8, (byte) 0xad, 0x21};
        String b64encoded1 = Base64.getEncoder().encodeToString(input1);
        String b64encoded2 = Base64.getEncoder().withoutPadding().encodeToString(input1);
        System.out.println(b64encoded1);
        System.out.println(b64encoded2);
        byte[] output1 = Base64.getDecoder().decode(b64encoded2);
        System.out.println(Arrays.toString(output1));

        //因为标准的Base64编码会出现+、/和=，所以不适合把Base64编码后的字符串放到URL中。
        // 一种针对URL的Base64编码可以在URL中使用的Base64编码，它仅仅是把+变成-，/变成_
        byte[] input2 = new byte[]{0x01, 0x02, 0x7f, 0x00};
        String b64encoded3 = Base64.getUrlEncoder().encodeToString(input2);
        System.out.println(b64encoded3);
        byte[] output2 = Base64.getUrlDecoder().decode(b64encoded3);
        System.out.println(Arrays.toString(output2));

        //哈希算法（Hash）又称摘要算法（Digest），它的作用是：对任意一组输入数据进行计算，得到一个固定长度的输出摘要。
        //哈希算法的目的就是为了验证原始数据是否被篡改。
        //Java字符串的hashCode()就是一个哈希算法，它的输入是任意字符串，输出是固定的4字节int整数
        System.out.println(Integer.toHexString("hello".hashCode()));
        System.out.println("hello".hashCode());
        System.out.println("hello world".hashCode());

        //Java标准库提供了常用的哈希算法，并且有一套统一的接口。
        //使用MessageDigest时，我们首先根据哈希算法获取一个MessageDigest实例，然后，反复调用update(byte[])输入数据。
        // 当输入结束后，调用digest()方法获得byte[]数组表示的摘要，最后，把它转换为十六进制的字符串。
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update("Hello".getBytes("UTF-8"));
        md.update("World".getBytes("UTF-8"));
        byte[] result = md.digest();
        System.out.println(new BigInteger(1, result).toString(16));

        //即使用户使用了常用口令，我们也可以采取措施来抵御彩虹表攻击，方法是对每个口令额外添加随机数，这个方法称之为加盐（salt）
        //digest = md5(salt+inputPassword)
        //加盐的目的在于使黑客的彩虹表失效，即使用户使用常用口令，也无法从MD5反推原始口令。

        //在Java中使用SHA-1，和MD5完全一样，只需要把算法名称改为"SHA-1"：
        MessageDigest md1 = MessageDigest.getInstance("SHA-1");
        md1.update("Hello".getBytes("UTF-8"));
        md1.update("World".getBytes("UTF-8"));
        byte[] result1 = md1.digest(); // 20 bytes: 6f44e49f848dd8ed27f73f59ab5bd4631b3f6b0d
        System.out.println(new BigInteger(1, result1).toString(16));

        //BouncyCastle就是一个提供了很多哈希算法和加密算法的第三方库,它提供了Java标准库没有的一些算法
        //Java标准库的java.security包提供了一种标准机制，允许第三方提供商无缝接入
        //我们要使用BouncyCastle提供的RipeMD160算法，需要先把BouncyCastle注册一下
        //注册只需要在启动时进行一次，后续就可以使用BouncyCastle提供的所有哈希算法和加密算法。
        /**
         * 注册BouncyCastle:
         */
        Security.addProvider(new BouncyCastleProvider());
        // 按名称正常调用:
        MessageDigest md2 = MessageDigest.getInstance("RipeMD160");
        md2.update("HelloWorld".getBytes("UTF-8"));
        byte[] result2 = md2.digest();
        System.out.println(new BigInteger(1, result2).toString(16));

        //Hmac算法就是一种基于密钥的消息认证码算法，它的全称是Hash-based Message Authentication Code，是一种更安全的消息摘要算法。
        //Hmac算法总是和某种哈希算法配合起来用的。例如，我们使用MD5算法，对应的就是HmacMD5算法，它相当于“加盐”的MD5
        //使用HmacMD5而不是用MD5加salt，有如下好处：
        //    HmacMD5使用的key长度是64字节，更安全；
        //    Hmac是标准算法，同样适用于SHA-1等其他哈希算法；
        //    Hmac输出和原有的哈希算法长度一致。
        //为了保证安全，我们不会自己指定key，而是通过Java标准库的KeyGenerator生成一个安全的随机的key。
        /**
         * 使用HmacMD5的步骤是：
         *
         * 通过名称HmacMD5获取KeyGenerator实例；
         * 通过KeyGenerator创建一个SecretKey实例；
         * 通过名称HmacMD5获取Mac实例；
         * 用SecretKey初始化Mac实例；
         * 对Mac实例反复调用update(byte[])输入数据；
         * 调用Mac实例的doFinal()获取最终的哈希值。
         */
        KeyGenerator kg = KeyGenerator.getInstance("HmacMD5");
        SecretKey key = kg.generateKey();
        byte[] skey = key.getEncoded();
        System.out.println(Arrays.toString(skey));
        System.out.println(new BigInteger(1, skey).toString(16));
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        mac.update("HelloWorld".getBytes("UTF-8"));
        byte[] result3 = mac.doFinal();
        System.out.println(new BigInteger(1, result3).toString(16));

        //因此，存储用户名和口令的数据库结构如下：
        //username	secret_key (64 bytes)	password

        /**
         * 有了Hmac计算的哈希和SecretKey，我们想要验证怎么办？
         * 这时，SecretKey不能从KeyGenerator生成，而是从一个byte[]数组恢复
         */
        //恢复SecretKey获取用于初始化Mac的key
        SecretKey key1 = new SecretKeySpec(skey, "HmacMD5");
        Mac mac1 = Mac.getInstance("HmacMD5");
        mac1.init(key1);
        mac1.update("HelloWorld".getBytes("UTF-8"));
        byte[] result4 = mac1.doFinal();
        System.out.println(Arrays.toString(result4));
        System.out.println(new BigInteger(1, result4).toString(16));


        //对称加密算法就是传统的用一个密码进行加密和解密
        //在软件开发中，常用的对称加密算法有：DES AES IDEA
        //AES算法是目前应用最广泛的加密算法
        //DES算法由于密钥过短，可以在短时间内被暴力破解，所以现在已经不安全了。
        //密钥长度直接决定加密强度，而工作模式和填充模式可以看成是对称加密算法的参数和格式选择。
        //Java标准库提供的算法实现并不包括所有的工作模式和所有填充模式，但是通常我们只需要挑选常用的使用就可以了。
        /**
         * Java标准库提供的对称加密接口非常简单，使用时按以下步骤编写代码：
         *
         * 根据 算法名称/工作模式/填充模式 获取 Cipher实例；
         * 根据 算法名称 初始化一个 SecretKey实例，密钥 必须是 指定长度；
         * 使 用SerectKey初始化 Cipher实例，并 设置加密或解密模式；
         * 传入 明文或密文，获得密文或明文。
         */
        //ECB模式是最简单的AES加密模式，它只需要一个固定长度的密钥，固定的明文会生成固定的密文，这种一对一的加密方式会导致安全性降低，
        // 更好的方式是通过CBC模式，它需要一个随机数作为IV参数，这样对于同一份明文，每次生成的密文都不同
        // 原文:
        String message = "Hello, world!";
        System.out.println("Message: " + message);
        // 128位密钥 = 16 bytes Key:
        byte[] keyt = "0123456789abcdef".getBytes("UTF-8");
        // 加密:
        byte[] data = message.getBytes("UTF-8");
        //byte[] encrypted = encryptECB(keyt, data);
        byte[] encrypted = encryptCBC(keyt, data);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));
        // 解密:
        //byte[] decrypted = decryptECB(keyt, encrypted);
        byte[] decrypted = decryptCBC(keyt, encrypted);
        System.out.println("Decrypted: " + new String(decrypted, "UTF-8"));

        //对称加密算法决定了口令必须是固定长度，然后对明文进行分块加密。
        // 又因为安全需求，口令长度往往都是128位以上，即至少16个字符。
        //实际上用户输入的口令并不能直接作为AES的密钥进行加密（除非长度恰好是128/192/256位），
        // 并且用户输入的口令一般都有规律，安全性远远不如安全随机数产生的随机口令。
        // 因此，用户输入的口令，通常还需要使用PBE算法，采用随机数杂凑计算出真正的密钥，再进行加密。
        //PBE的作用就是把用户输入的口令和一个安全随机的口令采用杂凑后计算出真正的密钥
        //PBE算法内部使用的仍然是标准对称加密算法（例如AES）
        // 把BouncyCastle作为Provider添加到java.security:
        Security.addProvider(new BouncyCastleProvider());
        // 原文:
        String message1 = "Hello, world!";
        // 加密口令:
        String password = "hello12345";
        // 16 bytes随机Salt:
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        System.out.printf("salt: %032x\n", new BigInteger(1, salt));
        // 加密:
        byte[] data1 = message1.getBytes("UTF-8");
        byte[] encrypted1 = encryptPBE(password, salt, data1);
        System.out.println("encrypted: " + Base64.getEncoder().encodeToString(encrypted1));
        // 解密:
        byte[] decrypted1 = decryptPBE(password, salt, encrypted1);
        System.out.println("decrypted: " + new String(decrypted1, "UTF-8"));


        //Diffie-Hellman算法。
        //DH算法解决了密钥在双方不直接传递密钥的情况下完成密钥交换，这个神奇的交换原理完全由数学理论支持。
        //更确切地说，DH算法是一个密钥协商算法，双方最终协商出一个共同的密钥，而这个密钥不会通过网络传输。
        //但是DH算法并未解决中间人攻击，即甲乙双方并不能确保与自己通信的是否真的是对方。
        // Bob和Alice:
        PersonDH bob = new PersonDH("Bob");
        PersonDH alice = new PersonDH("Alice");
        // 各自生成KeyPair:
        bob.generateKeyPair();
        alice.generateKeyPair();
        // 双方交换各自的PublicKey:
        // Bob根据Alice的PublicKey生成自己的本地密钥:
        bob.generateSecretKey(alice.publicKey.getEncoded());
        // Alice根据Bob的PublicKey生成自己的本地密钥:
        alice.generateSecretKey(bob.publicKey.getEncoded());
        // 检查双方的本地密钥是否相同:
        bob.printKeys();
        alice.printKeys();
        // 双方的SecretKey相同，后续通信将使用SecretKey作为密钥进行AES加解密...


        //非对称加密就是加密和解密使用的不是相同的密钥：只有同一个公钥-私钥对才能正常加解密。
        //非对称加密可以安全地公开各自的公钥，在N个人之间通信的时候：使用非对称加密只需要N个密钥对，每个人只管理自己的密钥对
        //非对称加密的缺点就是运算速度非常慢，比对称加密要慢很多
        //在实际应用的时候，非对称加密总是和对称加密一起使用
        //非对称加密实际上应用在第一步，即加密“AES口令”
        //在浏览器中常用的HTTPS协议的做法，即浏览器和服务器先通过RSA交换AES口令，
        // 接下来双方通信实际上采用的是速度较快的AES对称加密，而不是缓慢的RSA非对称加密。
        //用AES加密任意长度的明文，用RSA加密AES口令。

        //非对称加密的典型算法就是RSA算法
        // 明文:
        byte[] plain = "Hello, encrypt use RSA".getBytes("UTF-8");
        // 创建公钥／私钥对:
        PersonRSA alice1 = new PersonRSA("Alice");
        // 用Alice的公钥加密:
        byte[] pk = alice1.getPublicKey();
        System.out.println(String.format("public key: %x", new BigInteger(1, pk)));
        byte[] encryptedA = alice1.encrypt(plain);
        System.out.println(String.format("encrypted: %x", new BigInteger(1, encryptedA)));
        // 用Alice的私钥解密:
        byte[] sk = alice1.getPrivateKey();
        System.out.println(String.format("private key: %x", new BigInteger(1, sk)));
        byte[] decryptedA = alice1.decrypt(encryptedA);
        System.out.println(new String(decryptedA, "UTF-8"));


        //数字签名的目的是为了确认某个信息确实是由某个发送方发送的，任何人都不可能伪造消息，并且，发送方也不能抵赖。
        //在实际应用的时候，签名实际上并不是针对原始消息，而是针对原始消息的哈希进行签名
        //因为用户总是使用自己的私钥进行签名，所以，私钥就相当于用户身份。而公钥用来给外部验证用户身份。
        //常用数字签名算法有：
        //MD5withRSA
        //SHA1withRSA
        //SHA256withRSA

        // 生成RSA公钥/私钥:
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();
        PrivateKey sk1 = kp.getPrivate();
        PublicKey pk1 = kp.getPublic();
        // 待签名的消息:
        byte[] messages = "Hello, I am Bob!".getBytes(StandardCharsets.UTF_8);
        // 用私钥签名:
        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(sk1);
        s.update(messages);
        byte[] signed = s.sign();
        System.out.println(String.format("signature: %x", new BigInteger(1, signed)));
        // 用公钥验证:
        Signature v = Signature.getInstance("SHA1withRSA");
        v.initVerify(pk1);
        v.update(messages);
        boolean valid = v.verify(signed);
        System.out.println("valid? " + valid);

        //除了RSA可以签名外，还可以使用DSA算法进行签名。DSA是Digital Signature Algorithm的缩写，它使用ElGamal数字签名算法。
        //DSA只能配合SHA使用，常用的算法有：
        //SHA1withDSA
        //SHA256withDSA
        //SHA512withDSA
        //和RSA数字签名相比，DSA的优点是更快。

        //椭圆曲线签名算法ECDSA：Elliptic Curve Digital Signature Algorithm也是一种常用的签名算法，
        // 它的特点是可以从私钥推出公钥。比特币的签名算法就采用了ECDSA算法，使用标准椭圆曲线secp256k1。
        // BouncyCastle提供了ECDSA的完整实现。

        //摘要算法用来确保数据没有被篡改，非对称加密算法可以对数据进行加解密，签名算法可以确保数据完整性和抗否认性，
        // 把这些算法集合到一起，并搞一套完善的标准，这就是数字证书。
        //数字证书可以防止中间人攻击，因为它采用链式签名认证，即通过根证书（Root CA）去签名下一级证书，
        // 这样层层签名，直到最终的用户证书。而Root CA证书内置于操作系统中，
        // 所以，任何经过CA认证的数字证书都可以对其本身进行校验，确保证书本身不是伪造的。
        //在Java程序中，数字证书存储在一种Java专用的key store文件中，JDK提供了一系列命令来创建和管理key store
        //数字证书存储的是公钥，以及相关的证书链和算法信息。私钥必须严格保密，如果数字证书对应的私钥泄漏，就会造成严重的安全威胁。


    }

    // 加密:
    public static byte[] encryptPBE(String password, byte[] salt, byte[] input) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        //使用PBE时，我们还需要引入BouncyCastle，并指定算法是PBEwithSHA1and128bitAES-CBC-BC
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);

        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.ENCRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);
    }

    // 解密:
    public static byte[] decryptPBE(String password, byte[] salt, byte[] input) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);

        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.DECRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);
    }


    // 加密:
    public static byte[] encryptCBC(byte[] key, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        // CBC模式需要生成一个16 bytes的initialization vector:
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] iv = sr.generateSeed(16);
        IvParameterSpec ivps = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivps);
        byte[] data = cipher.doFinal(input);
        // IV不需要保密，把IV和密文一起返回:
        return join(iv, data);
    }

    // 解密:
    public static byte[] decryptCBC(byte[] key, byte[] input) throws GeneralSecurityException {
        // 把input分割成IV和密文:
        byte[] iv = new byte[16];
        byte[] data = new byte[input.length - 16];
        System.arraycopy(input, 0, iv, 0, 16);
        System.arraycopy(input, 16, data, 0, data.length);

        // 解密:
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivps);
        return cipher.doFinal(data);
    }

    public static byte[] join(byte[] bs1, byte[] bs2) {
        byte[] r = new byte[bs1.length + bs2.length];
        //数组复制: bs1[0...]-->r[0,len1), bs2[0...]--r[len1,len2)
        System.arraycopy(bs1, 0, r, 0, bs1.length);
        System.arraycopy(bs2, 0, r, bs1.length, bs2.length);
        return r;
    }

    // 加密:
    public static byte[] encryptECB(byte[] key, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//算法名称/工作模式/填充模式 获取 Cipher实例
        SecretKey keySpec = new SecretKeySpec(key, "AES");//根据 算法名称 初始化一个 SecretKey实例，密钥 必须是 指定长度；
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);//用SerectKey初始化 Cipher实例，并 设置加密模式；
        return cipher.doFinal(input);
    }

    // 解密:
    public static byte[] decryptECB(byte[] key, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }


}

class PersonRSA {
    String name;
    // 私钥:
    PrivateKey sk;
    // 公钥:
    PublicKey pk;

    public PersonRSA(String name) throws GeneralSecurityException {
        this.name = name;
        // 生成公钥／私钥对:
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();
        this.sk = kp.getPrivate();
        this.pk = kp.getPublic();
    }

    // 把私钥导出为字节
    public byte[] getPrivateKey() {
        return this.sk.getEncoded();
    }

    // 把公钥导出为字节
    public byte[] getPublicKey() {
        return this.pk.getEncoded();
    }

    // 用公钥加密:
    public byte[] encrypt(byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.pk);
        return cipher.doFinal(message);
    }

    // 用私钥解密:
    public byte[] decrypt(byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.sk);
        return cipher.doFinal(input);
    }
}

class PersonDH {
    public final String name;

    public PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] secretKey;

    public PersonDH(String name) {
        this.name = name;
    }

    // 生成本地KeyPair:
    public void generateKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH");
            kpGen.initialize(512);
            KeyPair kp = kpGen.generateKeyPair();
            this.privateKey = kp.getPrivate();  //私钥
            this.publicKey = kp.getPublic();    //公钥
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void generateSecretKey(byte[] receivedPubKeyBytes) {
        try {
            // 从byte[]恢复PublicKey:
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("DH");
            PublicKey receivedPublicKey = kf.generatePublic(keySpec);
            // 生成本地密钥:
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(this.privateKey); // 自己的PrivateKey
            keyAgreement.doPhase(receivedPublicKey, true); // 对方的PublicKey
            // 生成SecretKey密钥:
            this.secretKey = keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void printKeys() {
        System.out.printf("Name: %s\n", this.name);
        System.out.printf("Private key: %x\n", new BigInteger(1, this.privateKey.getEncoded()));
        System.out.printf("Public key: %x\n", new BigInteger(1, this.publicKey.getEncoded()));
        System.out.printf("Secret key: %x\n", new BigInteger(1, this.secretKey));
    }
}
