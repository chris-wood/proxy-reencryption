public class Identity 
{
	private String identity;

	public Identity(String id) {
		this.identity = id;
	}	

	public String getIdentity() {
		return identity;
	}

	@Override
	public String toString() {
		return identity;
	}
}