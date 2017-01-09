
public class Utilitaire {


	public static String lire_jusqua(String chaine_a_couper, String sepateur) {
		return (chaine_a_couper.split(sepateur))[0];
	}

	
	/*Fonction prise ailleurs*/
	public static String bytesToIp(byte[] bytes){
		int i = 4;
		String result = "";
		for (byte b : bytes) {
			result += b & 0xFF;
			if (--i > 0) 
				result += ".";
		}
		return result;
	}
	
	
	/*Fonction prise ailleurs*/
	public static String macAddressToString(byte[] bytes) {
		String result = "";
		for (byte b : bytes) {
			if (result.length() > 0) {
				result += ":";
			}
			result += String.format("%02x", b);
		}
		return result;
	}
	
	
	
	
	
}
