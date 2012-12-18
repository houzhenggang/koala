package org.koala.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;

import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

public class XmlRWUtil {

	private final static Logger logger = Logger.getLogger(XmlRWUtil.class);

	private static XmlRWUtil xmlReadWrite = null;

	private static Object obj = new Object();

	private XmlRWUtil() {
	}

	/**
	 * 获取读取XML的实例
	 * 
	 * @return XMLReader
	 */
	public static XmlRWUtil getInstance() {
		if (xmlReadWrite == null) {
			synchronized (obj) {
				if (xmlReadWrite == null) {
					xmlReadWrite = new XmlRWUtil();
				}
			}
		}
		return xmlReadWrite;
	}

	/**
	 * 读取XML文件
	 * 
	 * @param xmlPath
	 *            String
	 * @throws DocumentException
	 * @throws Exception
	 * @return Document
	 */
	public Document read(String xmlPath) throws Exception {
		SAXReader reader = new SAXReader();
		Document doc = reader.read(new File(getRealPath(xmlPath)));
		return doc;
	}

	/**
	 * 写xml
	 * 
	 */
	public void write(Document document, String xmlPath, String encoding)
			throws Exception {
		OutputFormat format = OutputFormat.createCompactFormat();
		format.setEncoding(encoding);
		XMLWriter writer = null;
		try {
			writer = new XMLWriter(new OutputStreamWriter(new FileOutputStream(
					getRealPath(xmlPath)), encoding), format);
			writer.write(document);
		} finally {
			if (writer != null)
				writer.close();
		}

	}

	/**
	 * 文件的相对路
	 * 
	 * @param path
	 *            String
	 * @return String
	 */
	public String getRealPath(String path) {
		URL url = null;
		try {
			url = this.getClass().getClassLoader().getResource(path);
			if (url == null) {
				url = this.getClass().getClassLoader().getResource("");
				File f = new File(url.getFile() + path);
				if (!f.exists()) {
					File pf = new File(f.getParent());
					logger.info(pf.getPath());
					if (pf.isDirectory() && !pf.exists())
						pf.mkdirs();
					f.createNewFile();
					return f.getPath();
				}
			}
		} catch (Exception e) {
			logger.error("ERROR:", e.fillInStackTrace());
		}
		return url.getFile();
	}
}
