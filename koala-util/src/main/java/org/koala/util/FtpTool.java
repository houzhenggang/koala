package org.koala.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.log4j.Logger;

public class FtpTool {

    private FTPClient fc = null;
    private static final Logger logger = Logger.getLogger(FtpTool.class);

    public FTPClient getFc() {
        if (fc == null) {
            fc = new FTPClient();
        }
        return fc;
    }

    public FtpTool() {
    }

    public void uploadFile(File f) {
        if (this.getFc().isConnected()) {
            InputStream in = null;
            try {
                in = new FileInputStream(f);
                logger.info("The name of file is " + f.getName() + ",[start upload]");
                this.getFc().storeFile(f.getName(), in);
                logger.info("[end upload]");
            } catch (Exception e) {
                logger.error("Error", e.fillInStackTrace());
            } finally {
                try {
                    if (in != null) {
                        in.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } else {
            logger.error("[uload file failed!]");
        }
    }

    public void connect(String hostname, int port, String username, String password) {
        try {
            logger.fatal("Connect to :" + hostname + "|" + port + "|" + username + "|" + password);
            this.getFc().connect(hostname, port);
            this.getFc().login(username, password);
            this.getFc().setFileTransferMode(FTP.STREAM_TRANSFER_MODE);
            this.getFc().setFileType(FTP.BINARY_FILE_TYPE);
            this.getFc().enterLocalPassiveMode();
            this.getFc().setSoTimeout(10000);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("[ftp login failed!]");
        }
    }

    public void downloadFile(String remote, FileOutputStream local) {
        try {
            this.getFc().retrieveFile(remote, local);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void logout() {
        try {
            this.getFc().logout();
            this.getFc().disconnect();
            logger.fatal("Ftp stop!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void uploadDir(File dir) {
        if (this.getFc().isConnected()) {
            File[] fs = dir.listFiles();
            for (File f : fs) {
                if (f != null && f.isFile()) {
                    //遍历上传
                    uploadFile(f);
                }
            }
            for (File f : fs) {
                if (f != null && f.isFile()) {
                    //备份文件
                    backup(f);
                }
            }
        } else {
            logger.error("[upload dir failed.]");
        }
    }

    private void backup(File f) {
        if (f != null && f.exists()) {
            File dir = new File(f.getParent());
            boolean flag = f.renameTo(new File(dir.getParent(), f.getName()));
            if (!flag) {
                f.delete();
                logger.error("Clear Error:[" + f.getPath() + "]");
            }
        }
    }
}
