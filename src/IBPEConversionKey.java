import it.unisa.dia.gas.jpbc.Element;

public class IBPEConversionKey
{
	public byte[] _N;
	public Element _R;
	public IBPEConversionKey(byte[] N, Element R)
	{
		this._N = N;
		this._R = R.duplicate();
	}
}