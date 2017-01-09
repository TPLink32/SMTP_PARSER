
public class Frame {
	int numero_de_frame = 0;  
	String information;  
	
	Frame(int l) {
		this.numero_de_frame = l;
		this.information = "";
		
	}

	void add(String s){
		information = information + s;
	}

	public int getNumero_de_frame() {
		return numero_de_frame;
	}

	public void setNumero_de_frame(int numero_de_frame) {
		this.numero_de_frame = numero_de_frame;
	}

	public String getInformation() {
		return information;
	}

	public void setInformation(String information) {
		this.information = information;
	}
	
	
}
