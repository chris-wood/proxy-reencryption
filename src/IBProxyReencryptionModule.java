// Standard Java classes
import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

// jPBC library classes
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBProxyReencryptionModule
{
	static void error(String s) { System.err.println(s); }
	static void disp(String s) { System.out.println(s); }

	public static Field G1, G2, GT, Zr;
	public static Pairing pairing;
	public static IBPEPublicParameters params;
	public static int n;
	public static int k;
	public static int msgSize;

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
		// CurveGenerator curveGenerator = new TypeACurveGenerator(rBits, qBits);

		// Generate the parameters...
		// CurveParameters cParams = curveGenerator.generate();

		// Print them on the screen...
		// System.out.println(cParams); 

		// Write them to the desired file (curves are generated on demand)
		// try
		// {	
		// 	PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(curveFile)));
		// 	writer.println(cParams);
		// 	writer.flush();
		// 	writer.close();
		// }
		// catch (Exception e)
		// {
		// 	error(e.getMessage());
		// 	e.printStackTrace();
		// 	System.exit(-1);
		// }

		// Assume curve properties stored in the file "curve.properties"
		pairing = PairingFactory.getPairing(curveFile);
		System.out.println(pairing.isSymmetric());

		// Grab a reference to the pairing fields
		G1 = pairing.getG1();
		G2 = pairing.getG2();
		GT = pairing.getGT();
		Zr = pairing.getZr();
		// disp("" + G1.getOrder());
		// disp("" + G2.getOrder());
		// disp("" + GT.getOrder());
		// disp("" + Zr.getOrder());
		disp("G1 length in bytes: " + G1.getLengthInBytes());
		disp("Zr length in bytes: " + Zr.getLengthInBytes()); // this is the message size, * 8 = security parameter

		// security - for the purpose of this implementation, we let n = k^1 (polynomial in terms of k)
		k = G1.getLengthInBytes() * 8; // this is the security parameter
		n = k; // for simplicity just fix n to be k, the security parameter
		msgSize = G1.getLengthInBytes();
		disp("Security parameter (k): " + k);

		////////////////////////////////
		// Setup()
		////////////////////////////////
		setup();
	}

	/**
	 * Setup()
	 *
	 * Create the master key and public parameters used in the scheme.
	 */
	private void setup()
	{
		g_s = G1.newRandomElement();
		g = g_s.duplicate();
		s = Zr.newRandomElement(); // msk (master secret key...)
		g_s.powZn(s); // DDL hardness
		params = new IBPEPublicParameters(g, g_s); // g_s = g^s
	}

	// TODO: move into separate, runnable task class
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

	// The five hash functions used by the scheme (paper claims six, but they only present 5 in the definitions)
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
		if (b.length != n) throw new Exception("Invalid blob dimension passed to H4 - must be of length n (polynomial in security paramter k)");
		byte[] sigma_r = new byte[e.toBytes().length + b.length];
		int ii = 0;
		for (int i = 0; i < e.toBytes().length; i++)
		{
			sigma_r[ii++] = e.toBytes()[i];
		}
		for (int i = 0; i < b.length; i++)
		{
			sigma_r[ii++] = b[i];
		}
		Element r = Zr.newRandomElement().setFromHash(sigma_r, 0, sigma_r.length);
		return r;
	}
	public static byte[] H5(Element e)
	{
		// hash(byte[] msg, byte[] digest)
		byte[] digest = new byte[n];
		Skein512.hash(e.toBytes(), digest); // we could use any 512-bit digest hash...
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

	public static void main(String[] args) throws Exception
	{
		if (args.length != 1)
		{
			error("usage: java pre_mg07 curve_properties_file");
			System.exit(-1);
		}

		String curveFile = args[0];

		disp("jPBC-based PE scheme");

		IBProxyReencryptionModule pe = new IBProxyReencryptionModule("curve.properties");

		//////////////////////////////////////////////////////////////////////
		///////// BEGIN THE IDENTITY-BASED PROXY REENCRYPTION SCHEME /////////
		//////////////////////////////////////////////////////////////////////

		int iterations = 200; // 10000000 sequential to get an estimated block size

		byte[] P_ID = "PRODUCER P".getBytes();
		byte[] A_ID = "CONSUMER A".getBytes();

		
		////////////////////////////////
		// Keygen(params, s = msk, id)
		////////////////////////////////
		// Element sk_P = H1(P_ID);
		// sk_P.powZn(s);
		// Element sk_A = H1(A_ID);
		// sk_A.powZn(s);
		Element sk_P = pe.generateSecretKey(P_ID);
		Element sk_A = pe.generateSecretKey(A_ID);

		// Create the encryption, reencryption, and decryption tasks
		IBPEEncryptionTask encryptor = new IBPEEncryptionTask(n, msgSize, pairing, pe.getGroupOrder(), pe.getGroupOrderPow(), pe.getMasterKey());
		IBPERKGenTask rkGenerator = new IBPERKGenTask(n, msgSize, pairing, pe.getGroupOrder(), pe.getGroupOrderPow(), pe.getMasterKey());
		IBPEReencryptionTask reencryptor = new IBPEReencryptionTask(n, msgSize, pairing, pe.getGroupOrder(), pe.getGroupOrderPow());
		IBPEDecryptionTask decryptor = new IBPEDecryptionTask(n, msgSize, pairing, pe.getGroupOrder(), pe.getGroupOrderPow());

		for (int itr = 1; itr <= iterations; itr++)
		{
			System.err.println("Iteration: " + itr);
			long encrTime = 0L;
			long decrTime = 0L;
			long reencTime = 0L;
			long rkGenTime = 0L;
			long ss, ee;
			long start = System.currentTimeMillis();
			for (int size = 0; size < itr; size++)
			{	
				// Our message is just some clever arrangement of (n) bytes, per the scheme description!
				byte[] M = new byte[n];
				for (int i = 0; i < M.length; i++) 
				{
					if (i % 2 == 0) M[i] = (byte)(0xE * itr);
					else M[i] = (byte)(0xF * itr);
				}

				////////////////////////////////
				// Encrypt(params, P_ID, m)
				////////////////////////////////
				ss = System.currentTimeMillis();

				IBPECiphertextLayerOne[] ct1 = encryptor.encrypt(params, P_ID, M);

				// // sigma Random(GT)
				// Element sigma = GT.newRandomElement();

				// // r = H4(sigma, m)
				// Element r = H4(sigma, M);

				// // A = g^r
				// Element A = g.duplicate().powZn(r);

				// // B = sigma * e(g^s, H1(ID)^r)
				// Element B = sigma.duplicate().mul(pairing.pairing(g_s, H1(P_ID).powZn(r)));

				// // C = m XOR H5(sigma)
				// byte[] C = XOR(M, H5(sigma));

				// // C' = Cbytes, where
				// // Cbytes is the array of bytes representing: (A, B, C)
				// byte[] Cbytes = new byte[P_ID.length + A.toBytes().length + B.toBytes().length + C.length];
				// int ii = 0;
				// for (int i = 0; i < P_ID.length; i++)
				// {
				// 	Cbytes[ii++] = P_ID[i];	
				// }
				// for (int i = 0; i < A.toBytes().length; i++)
				// {
				// 	Cbytes[ii++] = A.toBytes()[i];
				// }
				// for (int i = 0; i < B.toBytes().length; i++)
				// {
				// 	Cbytes[ii++] = B.toBytes()[i];	
				// }
				// for (int i = 0; i < C.length; i++)
				// {
				// 	Cbytes[ii++] = C[i];
				// }
				// Element S = H3(Cbytes).powZn(r);
				// IBPECiphertextLayerOne ct = new IBPECiphertextLayerOne(S, A, B, C); 

				ee = System.currentTimeMillis();
				encrTime += (ee - ss);

				////////////////////////////////
				// RKGen(params, P_sk, P_ID, A_ID)
				////////////////////////////////

				ss = System.currentTimeMillis();

				// // N = Random({0,1}^n)
				// byte[] N = random(n);
				// Element K = pairing.pairing(sk_P, H1(A_ID));

				// // Build K || id1 || id2 || N
				// byte[] concatArray = new byte[K.toBytes().length + P_ID.length + A_ID.length + N.length];
				// int ii = 0;
				// for (int i = 0; i < K.toBytes().length; i++)
				// {
				// 	concatArray[ii++] = K.toBytes()[i];
				// }
				// for (int i = 0; i < P_ID.length; i++)
				// {
				// 	concatArray[ii++] = P_ID[i];
				// }
				// for (int i = 0; i < A_ID.length; i++)
				// {
				// 	concatArray[ii++] = A_ID[i];
				// }
				// for (int i = 0; i < N.length; i++)
				// {
				// 	concatArray[ii++] = N[i];
				// }

				// // Curve is symmetric, G1 == G2, could use either...
				// Element R = H2(concatArray).mul(sk_P);
				// IBPEConversionKey rk = new IBPEConversionKey(N, R);

				IBPEConversionKey rk = rkGenerator.rkGen(params, sk_P, P_ID, A_ID);

				ee = System.currentTimeMillis();
				rkGenTime = (ee - ss);

				////////////////////////////////
				// Reencrypt(params, rk, ct(P_ID))
				////////////////////////////////

				ss = System.currentTimeMillis();

				IBPECiphertextLayerN[] ct2 = reencryptor.reencrypt(params, P_ID, rk, ct1);

				// concatArray = new byte[P_ID.length + ct._A.toBytes().length + ct._B.toBytes().length + ct._C.length];
				// ii = 0;
				// for (int i = 0; i < P_ID.length; i++)
				// {
				// 	concatArray[ii++] = P_ID[i];	
				// }
				// for (int i = 0; i < ct._A.toBytes().length; i++)
				// {
				// 	concatArray[ii++] = ct._A.toBytes()[i];
				// }
				// for (int i = 0; i < ct._B.toBytes().length; i++)
				// {
				// 	concatArray[ii++] = ct._B.toBytes()[i];	
				// }
				// for (int i = 0; i < ct._C.length; i++)
				// {
				// 	concatArray[ii++] = ct._C[i];	
				// }
				// Element h = H3(concatArray);
				// if (!(Arrays.equals(pairing.pairing(g.duplicate(), ct._S.duplicate()).toBytes(), pairing.pairing(h.duplicate(), ct._A.duplicate()).toBytes())))
				// {
				// 	System.out.println("Pairings didn't match. ABORT."); // test of reencryption.
				// 	System.exit(-1);
				// }

				// // t = Random(Zq)
				// Element t = Zr.newRandomElement();
				// // B' = B / (e(A, R * h^t) / e(g^t, S))
				// Element B_ = ct._B.duplicate().div(
				// 	pairing.pairing(ct._A.duplicate(), rk._R.duplicate().mul(h.powZn(t))).div(
				// 		pairing.pairing(g.duplicate().powZn(t), ct._S.duplicate())
				// 		));
				// IBPECiphertextLayerN ct2 = new IBPECiphertextLayerN(ct._A, B_, ct._C, P_ID, N);

				ee = System.currentTimeMillis();
				reencTime += (ee - ss);

				////////////////////////////////
				// Decrypt(params, sk_A, ct(P_ID -> A_ID))
				////////////////////////////////

				ss = System.currentTimeMillis();

				// // K = e(H1(P_ID), sk_A)
				// Element K_ = pairing.pairing(H1(ct2.ID), sk_A);
				// // sigma_ = B * e(A, H2(K || P_ID || A_ID || N))
				// concatArray = new byte[K_.toBytes().length + ct2.ID.length + A_ID.length + ct2._N.length];
				// ii = 0;
				// for (int i = 0; i < K.toBytes().length; i++)
				// {
				// 	concatArray[ii++] = K.toBytes()[i];
				// }
				// for (int i = 0; i < ct2.ID.length; i++)
				// {
				// 	concatArray[ii++] = ct2.ID[i];
				// }
				// for (int i = 0; i < A_ID.length; i++)
				// {
				// 	concatArray[ii++] = A_ID[i];
				// }
				// for (int i = 0; i < ct2._N.length; i++)
				// {
				// 	concatArray[ii++] = ct2._N[i];
				// }
				// Element sigma_ = ct2._B.duplicate().mul(pairing.pairing(ct2._A.duplicate(), H2(concatArray)));

				// // m' = C XOR (H5(sigma'))
				// byte[] M_ = XOR(ct2._C, H5(sigma_));

				// // r' = H4(sigma', m')
				// Element r_ = H4(sigma_, M_);

				// // VERIFICATION
				// if (!(Arrays.equals(ct2._A.toBytes(), g.duplicate().powZn(r_).toBytes())))
				// {
				// 	error("DECRYPTION VERIFICATION DID NOT PASS!");
				// 	System.exit(-1);
				// }

				byte[] M_ = decryptor.decryptLayerN(params, A_ID, sk_A, ct2);

				ee = System.currentTimeMillis();
				decrTime += (ee - ss);
			}
			long end = System.currentTimeMillis();
			disp(itr + "," + (msgSize * itr) + "B," + (encrTime) + "ms" + "," + (rkGenTime) + "ms" + "," + (reencTime) + "ms" + "," + (decrTime) + "ms" + "," + (end - start) + "ms");
			error(itr + "," + (msgSize * itr) + "B," + (encrTime) + "ms" + "," + (rkGenTime) + "ms" + "," + (reencTime) + "ms" + "," + (decrTime) + "ms" + "," + (end - start) + "ms");

		}


		// // Check passed, go ahead with steps 3/4 of reencryption
		// // t <- Random(Zr), B' = B / (e(A, R * h^t) / e(g^t, S))
		// Element t = Zr.newRandomElement();
		// Element numPair = pairing.pairing(ct._A.duplicate(), rk._R.duplicate().mul(h.duplicate().powZn(t)));
		// Element denPair = pairing.pairing(g.duplicate().powZn(t), ct._S.duplicate());
		// numPair.div(denPair);
		// Element B_ = ct._B.duplicate().div(numPair);
		// IBPECiphertextLayerN ct2 = new IBPECiphertextLayerN(ct._A, B_, ct._C, P_ID, rk._N);

		// // Decrypt the second level ciphertext
		// // Decrypt(params, sk_A, ct2)
		// Element newK = pairing.pairing(G1.newRandomElement().setFromHash(P_ID, 0, P_ID.length), sk_A);

		// // Build K || P_ID || A_ID || N
		// concatArray = new byte[newK.toBytes().length + ct2.ID.length + A_ID.length + ct2._N.toBytes().length];
		// ii = 0;
		// for (int i = 0; i < newK.toBytes().length; i++)
		// {
		// 	concatArray[ii++] = newK.toBytes()[i];
		// }
		// for (int i = 0; i < ct2.ID.length; i++)
		// {
		// 	concatArray[ii++] = ct2.ID[i];
		// }
		// for (int i = 0; i < A_ID.length; i++)
		// {
		// 	concatArray[ii++] = A_ID[i];
		// }
		// for (int i = 0; i < ct2._N.toBytes().length; i++)
		// {
		// 	concatArray[ii++] = ct2._N.toBytes()[i];
		// }

		// Element sigma_ = ct2._B.duplicate();
		// if (!(ct2._B.toString().equals(B_.toString())))
		// {
		// 	error("Sigma in CT and computed result don't match");
		// 	System.exit(-1);
		// }
		// sigma_.mul(pairing.pairing(ct2._A, G2.newRandomElement().setFromHash(concatArray, 0, concatArray.length)));

		// // C = m XOR H5(sigma)
		// tmp = GT.newRandomElement().setFromHash(sigma_.toBytes(), 0, sigma_.toBytes().length);
		// // BigInteger M_ = ct2._C.xor(tmp.toBigInteger());
		// byte[] M_ = XOR(ct2._C, tmp.toBytes());

		// byte[] sigma_r = new byte[M_.length + sigma_.toBytes().length];
		// ii = 0;
		// for (int i = 0; i < M_.length; i++)
		// {
		// 	sigma_r[ii++] = M_[i];
		// }
		// for (int i = 0; i < sigma_.toBytes().length; i++)
		// {
		// 	sigma_r[ii++] = sigma_.toBytes()[i];	
		// }

		// // Build a new exponent from the random sigma value
		// Element r_ = Zr.newRandomElement().setFromHash(sigma_r, 0, sigma_r.length);
		// // System.out.println(ct2._A);
		// // System.out.println(g.duplicate().powZn(r_));
		// if (!(Arrays.equals(ct2._A.toBytes(), g.duplicate().powZn(r_).toBytes())))
		// {
		// 	System.out.println("Second level decryption failed. ABORT");
		// 	System.exit(-1);
		// }

		// // byte[] dm = GT.newElement(M_).toBytes();
		// Element dm = GT.newRandomElement();
		// dm.setFromBytes(M_);
		// byte[] decryptedM = dm.toBytes();

		// long end = System.currentTimeMillis();
		// System.out.println("Elapsed time: " + (end - start) + "ms");
		// System.out.println("Decrypted ciphertexts match?: " + Arrays.equals(decryptedM, M));
	}
}
