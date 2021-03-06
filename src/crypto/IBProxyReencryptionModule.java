import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBProxyReencryptionModule
{
	static void error(String s) { System.err.println(s); }
	static void disp(String s) { System.out.println(s); }

	public Field G1, G2, GT, Zr;
	public Pairing pairing;
	public IBPEPublicParameters params;
	public int n;
	public int k;
	public int msgSize;

	private Element g;
	private Element g_s;
	private Element s; // MASTER KEY

	public IBProxyReencryptionModule(String curveFile)
	{
		// Init the generator for a Type A curve
		// int rBits = 512; // r becomes the order of each field (q)
		// int qBits = 512; 
		int rBits = 160;
		int qBits = 512;

		// Assume curve properties stored in the file "curve.properties"
		pairing = PairingFactory.getPairing(curveFile);
		System.out.println(pairing.isSymmetric());

		// Grab a reference to the pairing fields
		G1 = pairing.getG1();
		G2 = pairing.getG2();
		GT = pairing.getGT();
		Zr = pairing.getZr();
		// disp("G1 length in bytes: " + G1.getLengthInBytes());
		// disp("Zr length in bytes: " + Zr.getLengthInBytes()); // this is the message size, * 8 = security parameter

		// security - for the purpose of this implementation, we let n = k^1 (polynomial in terms of k)
		k = G1.getLengthInBytes() * 8; // this is the security parameter
		n = k; // for simplicity just fix n to be k, the security parameter
		msgSize = G1.getLengthInBytes();
		// disp("Security parameter (k): " + k);

		setup();
	}

	private void setup()
	{
		g_s = G1.newRandomElement();
		g = g_s.duplicate();
		s = Zr.newRandomElement(); // msk (master secret key...)
		g_s.powZn(s); // DDL hardness
		params = new IBPEPublicParameters(g, g_s); // g_s = g^s
	}

	public Element generateSecretKey(byte[] ID)
	{
		Element sk = H1(ID);
		sk.powZn(s);
		return sk;
	}

	public static byte[] XOR(byte[] b1, byte[] b2)
	{
		if (b1.length != b2.length) return null;
		byte[] x = new byte[b1.length];
		for (int i = 0; i < b1.length; i++)
		{
			x[i] = (byte)((int)b1[i] ^ (int)b2[i]);
		}
		return x;
	}

	public Element getMasterKey()
	{
		return s;
	}

	public Element getGroupOrder()
	{
		return g;
	}

	public Element getGroupOrderPow()
	{
		return g_s;
	}

	public static Element H1(byte[] b)
	{
		return G1.newRandomElement().setFromHash(b, 0, b.length);
	}

	public static Element H2(byte[] b) // assumes a symmetric pairing, but it could very easily be asymmetric
	{
		return G1.newRandomElement().setFromHash(b, 0, b.length);
	}

	public static Element H3(byte[] b)
	{
		return G1.newRandomElement().setFromHash(b, 0, b.length);
	}

	public static Element H4(Element e, byte[] b) throws Exception
	{
		if (b.length != n) {
			throw new Exception("Invalid blob dimension passed to H4 - must be of length n (polynomial in security paramter k)");
		}

		byte[] sigma_r = new byte[e.toBytes().length + b.length];
		int ii = 0;
		for (int i = 0; i < e.toBytes().length; i++) {
			sigma_r[ii++] = e.toBytes()[i];
		}
		for (int i = 0; i < b.length; i++) {
			sigma_r[ii++] = b[i];
		}

		Element r = Zr.newRandomElement().setFromHash(sigma_r, 0, sigma_r.length);
		return r;
	}

	public static byte[] H5(Element e)
	{
		byte[] digest = new byte[n];
		Skein512.hash(e.toBytes(), digest); // NOTE: we could use any 512-bit digest hash.
		return digest;
	}
	
	public static byte[] random(int bits) throws Exception
	{
		if (bits % 8 != 0) throw new Exception("Invalid number of bits - must divide 8 (byte size)");
		byte[] b = new byte[bits / 8]; 
		Random r = new Random();
		for (int i = 0; i < b.length; i++) b[i] = (byte)r.nextInt();
		return b;
	}

	public IBPEEncryptionTask createEncryptor() {
		return new IBPEEncryptionTask(n, msgSize, pairing, getGroupOrder(), getGroupOrderPow(), getMasterKey());
	}

	public IBPERKGenTask createKeyGenerator() {
		return new IBPERKGenTask(n, msgSize, pairing, getGroupOrder(), getGroupOrderPow(), getMasterKey());
	}

	public IBPEReencryptionTask createReEncryptor() {
		return new IBPEReencryptionTask(n, msgSize, pairing, getGroupOrder(), getGroupOrderPow());
	}

	public IBPEDecryptionTask createDecryptor() {
		return new IBPEDecryptionTask(n, msgSize, pairing, getGroupOrder(), getGroupOrderPow())
	}

	public static void run(int itr, IBPEEncryptionTask encrypter, IBPERKGenTask generator, IBPEReencryptionTask reencrypter, IBPEDecryptionTask decrypter)
	{
		long start = System.currentTimeMillis();
		for (int size = 0; size < itr; size++)
		{	
			// Our message is just some clever arrangement of (n) bytes, per the scheme description!
			byte[] M = new byte[n];
			for (int i = 0; i < M.length; i++)  {
				if (i % 2 == 0) M[i] = (byte)(0xE * itr);
				else M[i] = (byte)(0xF * itr);
			}

			IBPECiphertextLayerOne[] ct1 = encrypter.encrypt(params, P_ID, M);
			IBPEConversionKey rk = rkGenerater.rkGen(params, sk_P, P_ID, A_ID);
			IBPECiphertextLayerN[] ct2 = reencrypter.reencrypt(params, P_ID, rk, ct1);

			byte[] M_ = decrypter.decryptLayerN(params, A_ID, sk_A, ct2);

			// TODO: M and M_ should be equal.
		}
		long end = System.currentTimeMillis();

		disp("" + (end - start));
		error("" + (end - start));
	}

	public static void main(String[] args) throws Exception
	{
		if (args.length != 1) {
			error("usage: java pre_mg07 curve_properties_file");
			System.exit(-1);
		}

		String curveFile = args[0];

		disp("jPBC-based PE scheme");

		IBProxyReencryptionModule pe = new IBProxyReencryptionModule("curve.properties");

		//////////////////////////////////////////////////////////////////////
		///////// BEGIN THE IDENTITY-BASED PROXY REENCRYPTION SCHEME /////////
		//////////////////////////////////////////////////////////////////////

		int iterations = 1; // 10000000 sequential to get an estimated block size

		Identity P_ID = new Identity("PRODUCER P");
		Identity A_ID = new Identity("CONSUMER C");
		
		// Keygen(params, s = msk, id)
		Element sk_P = pe.generateSecretKey(P_ID.getIdentityBytes());
		Element sk_A = pe.generateSecretKey(A_ID.getIdentityBytes());

		// Create the encryption, reencryption, and decryption tasks
		IBPEEncryptionTask encryptor = pe.createEncryptor();
		IBPERKGenTask rkGenerator = pe.createKeyGenerator();
		IBPEReencryptionTask reencryptor = pe.createReEncryptor();
		IBPEDecryptionTask decryptor = pe.createDecryptor();

		for (int itr = 1; itr <= iterations; itr++) {
			run(itr, P_ID, A_ID, encryptor, rkGenerator, reencryptor, decryptor);
			error("Iteration: " + itr);	
		}
	}
}
