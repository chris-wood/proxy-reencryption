// jPBC library classes
import it.unisa.dia.gas.jpbc.Element;

public class IBPECiphertextLayerN
{
	public Element _A;
	public Element _B;
	public byte[] _C;
	public byte[] ID;
	public byte[] _N;
	public IBPECiphertextLayerN(Element A, Element B, byte[] C, byte[] ID, byte[] N)
	{
		this._A = A.duplicate();
		this._B = B.duplicate();
		this._C = C; // TODO: should shallow copy this, not reassign references...
		this.ID = new byte[ID.length];
		for (int i = 0; i < ID.length; i++)
		{
			this.ID[i] = ID[i];
		}
		this._N = N;
	}
}