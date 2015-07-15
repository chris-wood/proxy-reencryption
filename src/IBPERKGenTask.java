import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBPERKGenTask 
{
	private int n;
	private int blockSize;
	private Pairing pairing;
	private Field G1;
	private Field GT;
	private Field Zr;
	private Element g;
	private Element g_s;
	private Element s;

	public IBPERKGenTask(int n, int blockSize, Pairing pairing, Element g, Element g_s, Element s) throws Exception
	{
		this.n = n;
		this.blockSize = blockSize;
		this.pairing = pairing;
		this.G1 = pairing.getG1();
		this.GT = pairing.getGT();
		this.Zr = pairing.getZr();
		this.g = g;
		this.g_s = g_s;
		this.s = s;
	}

	////////////////////////////////
	// RKGen(params, P_sk, P_ID, A_ID)
	////////////////////////////////
	public IBPEConversionKey rkGen(IBPEPublicParameters params, Element sk_P, byte[] P_ID, byte[] A_ID) throws Exception
	{
		// N = Random({0,1}^n)
		byte[] N = IBProxyReencryptionModule.random(n);
		Element K = pairing.pairing(sk_P, IBProxyReencryptionModule.H1(A_ID));

		// Build K || id1 || id2 || N
		byte[] concatArray = new byte[K.toBytes().length + P_ID.length + A_ID.length + N.length];
		int ii = 0;
		for (int i = 0; i < K.toBytes().length; i++)
		{
			concatArray[ii++] = K.toBytes()[i];
		}
		for (int i = 0; i < P_ID.length; i++)
		{
			concatArray[ii++] = P_ID[i];
		}
		for (int i = 0; i < A_ID.length; i++)
		{
			concatArray[ii++] = A_ID[i];
		}
		for (int i = 0; i < N.length; i++)
		{
			concatArray[ii++] = N[i];
		}

		// Curve is symmetric, G1 == G2, could use either...
		Element R = IBProxyReencryptionModule.H2(concatArray).mul(sk_P);

		IBPEConversionKey rk = new IBPEConversionKey(N, R);
		return rk;
	}
}
