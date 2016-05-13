package com.fsck.k9.crypto;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import android.support.annotation.Nullable;
import android.util.Log;

import com.fsck.k9.K9;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.RawDataBody;
import com.fsck.k9.mail.internet.SizeAware;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.DeferredFileOutputStream;

public class DecryptedTempFileBody implements RawDataBody, SizeAware {
    private final String encoding;

    private static final int MEMORY_BACKED_THRESHOLD = 1024 * 8;


    private final File tempDirectory;
    @Nullable
    private File file;
    @Nullable
    private byte[] data;


    public DecryptedTempFileBody(String encoding, File tempDirectory) {
        this.encoding = encoding;
        this.tempDirectory = tempDirectory;
    }

    @Override
    public String getEncoding() {
        return encoding;
    }

    @Override
    public void setEncoding(String encoding) throws MessagingException {
        throw new RuntimeException("Not supported");
    }

    public OutputStream getOutputStream() throws IOException {
        return new DeferredFileOutputStream(MEMORY_BACKED_THRESHOLD, "decrypted", null, tempDirectory) {
            @Override
            public void close() throws IOException {
                super.close();

                if (isThresholdExceeded()) {
                    file = getFile();
                } else {
                    data = getData();
                }
            }
        };
    }

    @Override
    public InputStream getInputStream() throws MessagingException {
        try {
            if (file != null) {
                Log.d(K9.LOG_TAG, "Decrypted data is file-backed.");
                return new FileInputStream(file);
            }
            if (data != null) {
                Log.d(K9.LOG_TAG, "Decrypted data is memory-backed.");
                return new ByteArrayInputStream(data);
            }

            throw new IllegalStateException("Data must be fully written before it can be read!");
        } catch (IOException ioe) {
            throw new MessagingException("Unable to open body", ioe);
        }
    }

    @Override
    public void writeTo(OutputStream out) throws IOException, MessagingException {
        InputStream in = getInputStream();
        try {
            IOUtils.copy(in, out);
        } finally {
            in.close();
        }
    }

    @Override
    public long getSize() {
        if (file != null) {
            return file.length();
        }
        if (data != null) {
            return data.length;
        }

        throw new IllegalStateException("Data must be fully written before it can be read!");
    }

    public File getFile() throws IOException {
        if (file == null) {
            writeMemoryToFile();
        }
        return file;
    }

    private void writeMemoryToFile() throws IOException {
        if (file != null) {
            throw new IllegalStateException("Body is already file-backed!");
        }
        if (data == null) {
            throw new IllegalStateException("Data must be fully written before it can be read!");
        }

        Log.d(K9.LOG_TAG, "Writing body to file for attachment access");

        file = File.createTempFile("decrypted", null, tempDirectory);

        FileOutputStream fos = new FileOutputStream(file);
        fos.write(data);
        fos.close();

        data = null;
    }
}
