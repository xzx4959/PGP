package com.alibaba.pgp.TestPGP;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
/**
 * A simple utility class that encrypts/decrypts public key based encryption
 * large files.
 */
public class KeyBasedLargeFileProcessor {
	public static void decryptFile(String inputFileName, String keyFileName, char[] passwd, String outFileName) throws IOException, NoSuchProviderException {
		InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
		InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
		decryptFile(in, keyIn, passwd, outFileName);
		keyIn.close();
		in.close();
	}
	public static void decryptFile(InputStream in, InputStream keyIn, char[] passwd, String outFileName) throws IOException, NoSuchProviderException {
		in = PGPUtil.getDecoderStream(in);
		try {
			PGPObjectFactory pgpF = new PGPObjectFactory(in);
			PGPEncryptedDataList enc;
			Object o = pgpF.nextObject();
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();

				sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
			}
			if (sKey == null) {
				throw new IllegalArgumentException("secret key for message not found.");
			}
			InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
			PGPObjectFactory plainFact = new PGPObjectFactory(clear);
			PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();
			InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
			PGPObjectFactory pgpFact = new PGPObjectFactory(compressedStream);
			Object message = pgpFact.nextObject();
			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				InputStream unc = ld.getInputStream();
				OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));
				Streams.pipeAll(unc, fOut);
				fOut.close();
			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("message is not a simple encrypted file - type unknown.");
			}
		} catch (PGPException e) {
			System.err.println(e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		}
	}

	public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException {
		if (armor) {
			out = new ArmoredOutputStream(out);
		}
		try {
			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
			cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
			OutputStream cOut = cPk.open(out, new byte[1 << 16]);
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);
			comData.close();
			cOut.close();
			if (armor) {
				out.close();
			}
		} catch (PGPException e) {
			System.err.println(e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		}
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String encode = "D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\encode.txt";
		String test = "D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\test.txt";
		String publicKey = "D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\public.asc";
		String text = "Hello how are you";
		OutputStream out = new BufferedOutputStream(new FileOutputStream(encode));
		PGPPublicKey encKey = PGPExampleUtil.readPublicKey(publicKey);
		encryptFile(out, test, encKey, true, false);
		out.close();
		InputStream inputStream = KeyBasedLargeFileProcessor.class.getClassLoader().getResourceAsStream("private.asc");
		decryptFile("D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\encode.txt", "D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\private.asc", "alitest".toCharArray(), "D:\\code\\TestPGP\\target\\classes\\com\\alibaba\\pgp\\TestPGP\\decode.txt");
	}
}