
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;



public class Main {

	public static void main(String argv[]) throws Exception{
		
		String chemin_du_fichier_entree = "Ressources/smtp.pcap";
		File fichier_sortie = new File("SMTP_DPI.txt");
		
		BufferedWriter b_writer = new BufferedWriter(new FileWriter(fichier_sortie));
		Ethernet ethernet = new Ethernet();
		Ip4 ip4 = new Ip4();
		Tcp tcp = new Tcp();
		Smtp smtp = new Smtp();

		final StringBuilder string_error_builder = new StringBuilder(); 
		JBuffer jbuffer = new JBuffer(JMemory.POINTER);
		PcapHeader pcap_header = new PcapHeader(JMemory.POINTER);
		final Pcap pcap_objet = Pcap.openOffline(chemin_du_fichier_entree, string_error_builder);  
		JScanner jscanner = new JScanner();

		while(pcap_objet.nextEx(pcap_header, jbuffer) >= 0){
			PcapPacket packet = new PcapPacket(pcap_header, jbuffer);
			jscanner.scan((JPacket) packet, JRegistry.mapDLTToId(pcap_objet.datalink()));
			Frame Frame_courrante = new Frame( (int) packet.getFrameNumber());
			Frame_courrante.add(Parse.Informations_du_Header_General(packet));

			if (packet.hasHeader(ethernet)){ Frame_courrante.add(Parse.Informations_du_Protocole_Ethernet(ethernet)); }
			if (packet.hasHeader(ip4)) { Frame_courrante.add(Parse.Informations_du_Protocole_IP(ip4));}
			if (packet.hasHeader(tcp)) { Frame_courrante.add(Parse.Informations_du_Protocole_TCP(tcp));}
			if (packet.hasHeader(smtp)) { Frame_courrante.add(Parse.Informations_du_Protocole_SMTP(smtp));
				// Eciture uniquement pour les frames avec SMTP ---------------------------------------------------------------
				b_writer.write(Frame_courrante.information);
			} 
		}
		
		
		b_writer.close();
		pcap_objet.close();
	
		System.exit(0);
	}


	
	
}





