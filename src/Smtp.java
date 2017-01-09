import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.tcpip.Tcp;


@Header
public class Smtp extends JHeader { 

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return  buffer.size() - offset;  
	}

	static {
			try {
				JRegistry.register(Smtp.class);
			} catch (RegistryHeaderErrors e) {
			
			}
	
	}
	
	
	public String getMessage() {  
		return new String(super.getByteArray(0, this.getHeaderLength()));  
	} 

	@Bind( to = Tcp.class )  
	public static  boolean bindToTcp(JPacket packet , Tcp tcp ) {  
		return ( tcp.source() == 25 || tcp.destination() == 25 );  
	}  

}
