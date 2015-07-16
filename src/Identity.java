public class Identity 
{
	private String identity;

	public Identity(String id) {
		this.identity = id;
	}	

	public String getIdentity() {
		return identity;
	}

	public byte[] getIdentityBytes() {
		return identity.getBytes();
	}

	@Override
	public String toString() {
		return identity;
	}
}