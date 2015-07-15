// jPBC library classes
import it.unisa.dia.gas.jpbc.Element;

public class IBPECiphertextLayerOne
{
	public Element _S;
	public Element _A; 
	public Element _B;
	public byte[] _C;
	
	public IBPECiphertextLayerOne(Element S, Element A, Element B, byte[] C)
	{
		this._S = S.duplicate();
		this._A = A.duplicate();
		this._B = B.duplicate();
		this._C = C; // TODO: should shallow copy this, not reassign references
	}
}