import java.io.BufferedReader;
import java.io.StringReader;
import java.sql.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Parse {

	
	 // CODE -----------------------------------
	static String S_221 = "221";
	static String S_220 = "220";
	static String S_334 = "334";
	static String S_235 = "235";
	static String S_250 = "250";
	static String S_354 = "354";
	
	
	static String EHLO = "EHLO";
	static String AUTH_LOGIN = "AUTH LOGIN" ;
	static String MAIL_FROM = "MAIL FROM";
	static String RCPT_TO = "RCPT TO";
	static String DATA = "DATA";
	static String QUIT = "QUIT";
	
	static String RESPONSE_CODE  = "Response Code:";
	static String COMMAND_LINE  = "Command line:" ;
	static String RESPONSE_PARAMETER = "Response parameter:" ;
	static String REQUEST_PARAMETER = "Request parameter:";
	
	static String FROM = "From:";
	static String TO = "To:";
	static String DATE = "Date:";
	static String SUBJECT = "Subject:";
	static String MESSAGE_ID = "Message-ID:";
	static String MIME_VERSION = "MIME-Version:";
	static String CONTENT_TYPE = "Content-Type:";
	static String X_MAILER = "X-Mailer:";
	static String THREAD_INDEX = "Thread-Index:";
	static String CONTENT_LANGUAGE = "Content-Language:";
	static String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding:";
	static String CONTENT_DISPOSITION = "Content-Disposition:";
	/*
	 * HEADER ---------------------------------------------------------------------------------------------
	 */
	static String Informations_du_Header_General(PcapPacket packet) {
		PcapHeader header_du_packet = packet.getCaptureHeader();
		DateFormat Format_de_la_date = new SimpleDateFormat("dd MMMM yyyy HH:mm:ss");
 
		return " --------------------------------------------------\n"
				+ "    Frame numéro " + packet.getFrameNumber() + "\n "
				+ "--------------------------------------------------\n"
				+ "        > Date d'arrivée: " + Format_de_la_date.format(new Date(header_du_packet.timestampInMillis())) + "\n"
				+ "        > Taille du paquet: " + header_du_packet.wirelen() + " bytes \n"
				+ "        > Taille de la capture : " + header_du_packet.caplen() + " bytes \n";
	}


	/*
	 * ETHERNET ---------------------------------------------------------------------------------------------
	 */
	 static String Informations_du_Protocole_Ethernet(Ethernet ethernet){
		return "\n    Ethernet --------------------------------------\n"	
				+ "        > Destination: " + Utilitaire.macAddressToString(ethernet.destination()) + "\n"
				+ "        > Source: "+ Utilitaire.macAddressToString(ethernet.source()) + "\n"
				+ "        > Type: " + ethernet.typeDescription() + "\n";
	}

	
	
	/*
	 * IP ---------------------------------------------------------------------------------------------
	 */
	static String Informations_du_Protocole_IP(Ip4 ip) {
		return "\n    IP --------------------------------------------\n"
				+ "        > Version: " + ip.getDescription() + "\n"
				+ "        > Taille du header IP: " + ip.getHeaderLength() + " bytes\n"
				+ "        > Taille totale: " + ip.length() +"\n"
				+ "        > ID :" + Integer.toHexString(ip.id()) + "\n"
				+ "        > FLAGS: " + String.format("%02d", ip.flags())+ "\n"
				+ "        > TTL (Time to Live):"+ ip.ttl() +"\n"
				+ "        > Checksum du Header: " + Integer.toHexString(ip.checksum()) + "\n"
				+ "        > Source: " + Utilitaire.bytesToIp(ip.source())+ "\n"
				+ "        > Destination: " + Utilitaire.bytesToIp(ip.destination()) + "\n";
	}	


	
	
	/*
	 * TCP ---------------------------------------------------------------------------------------------
	 */
	 static String Informations_du_Protocole_TCP(Tcp tcp) {
		 return	"\n    TCP -------------------------------------------\n"
				+ "        > Port Source: " + tcp.source() + "\n"
				+ "        > Port Destination: " + tcp.destination() + "\n"
				+ "        > Taille du header TCP: " + tcp.getLength() +" bytes\n";
	}
	 
	 
	/*
	 * UDP ---------------------------------------------------------------------------------------------
	 */
	static String Informations_du_Protocole_UDP(Udp udp) {
		return  "\n    UDP --------------------------------------------------\n"
				+ "        > Port Source " + udp.source() + "\n"
				+ "        > Port Destination: " + udp.destination() + "\n"
				+ "        > Taille du header UDP: " + udp.length() + "\n"
				+ "        > Chcksum du header TCP: "+ Integer.toHexString(udp.checksum()) + " \n";
	}

	
	
	/*
	 * SMTP ---------------------------------------------------------------------------------------------
	 */

	
	
	
	static String Informations_du_Protocole_SMTP(Smtp smtp) throws Exception {
		String message = smtp.getMessage();
		String result = "\n    SMTP --------------------------------------------------\n";
		
		BufferedReader Buffered_reader = new BufferedReader(new StringReader(message));
		String ligne_lue;
	
		while((ligne_lue = Buffered_reader.readLine()) != null) {
		ligne_lue = ligne_lue.trim();
		

			// CODE --------------------------
			if(ligne_lue.startsWith(S_221)){ result += "        > [CODE] : " + S_221 + " | " + ligne_lue.substring(3) + "\n"; }
			else if(ligne_lue.startsWith(S_220)){ result += "        > [CODE] : " + S_220 + " | " + ligne_lue.substring(3) + "\n"; }
			else if(ligne_lue.startsWith(S_334)){ result += "        > [CODE] : " + S_334 + " | " + ligne_lue.substring(3) + "\n"; }
			else if(ligne_lue.startsWith(S_235)){ result += "        > [CODE] : " + S_235 + " | " + ligne_lue.substring(3) + "\n"; }
			else if(ligne_lue.startsWith(S_250)){ result += "        > [CODE] : " + S_250 + " | " + ligne_lue.substring(3) + "\n"; }
			else if(ligne_lue.startsWith(S_354)){ result += "        > [CODE] : " + S_354 + " | " + ligne_lue.substring(3) + "\n"; }
			
			// COMMANDES -------------------------
			else if(ligne_lue.startsWith(EHLO)){result += "        > [ESMTP command] : " + EHLO + " | " + ligne_lue.substring(EHLO.length()) + "\n"; }
			else if(ligne_lue.startsWith(AUTH_LOGIN)){result += "        > [ESMTP command] : " + AUTH_LOGIN + " | " + ligne_lue.substring(AUTH_LOGIN.length()) + "\n"; }
			else if(ligne_lue.startsWith(MAIL_FROM)){result += "        > [ESMTP command] : " + MAIL_FROM + " | " + ligne_lue.substring(MAIL_FROM.length()) + "\n"; }
			else if(ligne_lue.startsWith(RCPT_TO)){result += "        > [ESMTP command] : " + RCPT_TO + " | " + ligne_lue.substring(RCPT_TO.length()) + "\n"; }
			else if(ligne_lue.startsWith(DATA)){result += "        > [ESMTP command] : " + DATA + " | " + ligne_lue.substring(DATA.length()) + "\n"; }
			else if(ligne_lue.startsWith(QUIT)){result += "        > [ESMTP command] : " + QUIT + " | " + ligne_lue.substring(QUIT.length()) + "\n"; }
			
			// AUTRES -----------------------------
			else if(ligne_lue.startsWith(RESPONSE_CODE)){result += "        > [RESPONSE_CODE] : "  + ligne_lue.substring(RESPONSE_CODE.length()) + "\n"; }
			else if(ligne_lue.startsWith(COMMAND_LINE)){result += "        > [COMMAND_LINE] : "  + ligne_lue.substring(COMMAND_LINE.length()) + "\n"; }
			else if(ligne_lue.startsWith(RESPONSE_PARAMETER)){result += "        > [RESPONSE_PARAMETER] : "  + ligne_lue.substring(RESPONSE_PARAMETER.length()) + "\n"; }
			else if(ligne_lue.startsWith(REQUEST_PARAMETER)){result += "        > [REQUEST_PARAMETER] : "  + ligne_lue.substring(REQUEST_PARAMETER.length()) + "\n"; }
				
			else if(ligne_lue.startsWith(FROM)){result += "        > [Champ] : " + FROM + " | " + ligne_lue.substring(FROM.length()) + "\n"; }
			else if(ligne_lue.startsWith(DATE)){result += "        > [Champ] : " + DATE + " | " + ligne_lue.substring(DATE.length()) + "\n"; }
			
			else if(ligne_lue.startsWith(TO)){result += "        > [Champ] : " + TO + " | " + ligne_lue.substring(TO.length()) + "\n"; }
			else if(ligne_lue.startsWith(SUBJECT)){result += "        > [Champ] : " + SUBJECT + " | " + ligne_lue.substring(SUBJECT.length()) + "\n"; }
			else if(ligne_lue.startsWith(MESSAGE_ID)){result += "        > [Champ] : " + MESSAGE_ID + " | " + ligne_lue.substring(MESSAGE_ID.length()) + "\n"; }
			else if(ligne_lue.startsWith(MIME_VERSION)){result += "        > [Champ] : " + MIME_VERSION + " | " + ligne_lue.substring(MIME_VERSION.length()) + "\n"; }
			else if(ligne_lue.startsWith(CONTENT_TYPE)){result += "        > [Champ] : " + CONTENT_TYPE + " | " + ligne_lue.substring(CONTENT_TYPE.length()) + "\n"; }
			else if(ligne_lue.startsWith(X_MAILER)){result += "        > [Champ] : " + X_MAILER + " | " + ligne_lue.substring(X_MAILER.length()) + "\n"; }
			else if(ligne_lue.startsWith(THREAD_INDEX)){result += "        > [Champ] : " + THREAD_INDEX + " | " + ligne_lue.substring(THREAD_INDEX.length()) + "\n"; }
			else if(ligne_lue.startsWith(CONTENT_LANGUAGE)){result += "        > [Champ] : " + CONTENT_LANGUAGE + " | " + ligne_lue.substring(CONTENT_LANGUAGE.length()) + "\n"; }
			else if(ligne_lue.startsWith(CONTENT_TRANSFER_ENCODING)){result += "        > [Champ] : " + CONTENT_TRANSFER_ENCODING + " | " + ligne_lue.substring(CONTENT_TRANSFER_ENCODING.length()) + "\n"; }
			else if(ligne_lue.startsWith(CONTENT_DISPOSITION)){result += "        > [Champ] : " + CONTENT_DISPOSITION + " | " + ligne_lue.substring(CONTENT_DISPOSITION.length()) + "\n"; }
			else {
				//result += "        > [DATA] : " + ligne_lue + "\n";
			}
			
		}
		
	
		return result + " \n";
		
	
	}

	
	
	
	
}
