package edu.udo.itmc.dev.blaesing.tsautils;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import org.bouncycastle.tsp.TimeStampToken;

/**
 *
 * @author matthias
 */
public class Main {

    public static void main(String[] args) throws Exception {
        

	byte[] data = "Hallo Welt".getBytes(StandardCharsets.UTF_8);

	DFNTimestampService ts = new DFNTimestampService();
	TimeStampToken token = ts.timestamp(new ByteArrayInputStream(data));

        System.out.println(ts.validate(new ByteArrayInputStream(data), token.getEncoded()).withZoneSameInstant(ZoneId.of("Europe/Berlin")));

//	try (FileOutputStream fos = new FileOutputStream("/home/matthias/test.tsr")) {
//	    fos.write(token.getEncoded());
//	}


    }

}
