import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class t {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		//		FileChannel inChannel;
		//		try {
		//			inChannel = new RandomAccessFile("/Users/peter/test1/fu", "rw").getChannel();
		//			ByteBuffer buffer = inChannel.map(FileChannel.MapMode.READ_WRITE, 0, 100);
		//			buffer.order(ByteOrder.nativeOrder());
		//			buffer.put((byte) 0x56);
		//		} catch (Exception e) {
		//			e.printStackTrace();
		//		}
		File file = new File("/Users/peter/test1/vmlinux");
		byte bytes[] = new byte[1024*1024*500];
		RandomAccessFile f;
		try {
			f = new RandomAccessFile(file, "r");

			f.seek(10);
			f.readFully(bytes);
			f.close();
			ByteBuffer buffer = ByteBuffer.wrap(bytes);
			buffer.order(ByteOrder.nativeOrder());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
