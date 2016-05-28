package com.fsck.k9.crypto;

import com.fsck.k9.mail.filter.EOLConvertingOutputStream;

import org.apache.james.mime4j.util.MimeUtil;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;


public class SaveSignedPartIS extends FilterInputStream {
    public SaveSignedPartIS(InputStream in){
        super(in);
    }

    private ByteArrayOutputStream line = new ByteArrayOutputStream();

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        int c = read();
        if (c == -1) {
            return -1;
        }

        b[off] = (byte) c;
        int i = 1;
        try {
            for (; i < len; i++) {
                c = read();
                if (c == -1) {
                    break;
                }
                b[off + i] = (byte) c;
            }

        } catch (IOException ee) {

        }
        return i;
    }

    public int read() throws IOException {
        int c = in.read();
        line.write(c);

        if (c == '\n'){
            state = state.next(line.toByteArray(), signedMap);
            line = new ByteArrayOutputStream();
        }

        return c;
    }

    private State state = State.LOOK_SIGNED_PART;

    private Map<String, byte[]> signedMap = new HashMap<String, byte[]>();

    public boolean isSaved(String boundary) {
        return signedMap.containsKey(boundary);
    }

    public void writeTo(String boundary, OutputStream out) throws IOException {
        byte[] signedPart = signedMap.remove(boundary);
        String str = new String(signedPart);
        out.write(signedPart, 0, signedPart.length - 2);
    }

    enum State {
        LOOK_SIGNED_PART, LOOK_BOUNDARY, STORE_PART, CONTINUE_CONTENT_TYPE;

        private final static Pattern CONTENT_TYPE = Pattern.compile("^Content-Type:", Pattern.CASE_INSENSITIVE);
        private final static Pattern EMPTY_LINE = Pattern.compile("^\r?\n");
        private final static Pattern NEW_HEADER = Pattern.compile("^[a-zA-Z]+:");

        private static String signedBoundary;

        private static ByteArrayOutputStream signedPartBuffer;
        private static OutputStream signedPartStream;

        public State next(byte[] byteLine, Map<String, byte[]> signedMap) {
            try {
                String line = new String(byteLine, "US-ASCII");
                switch (this) {
                    case LOOK_SIGNED_PART:
                        return lookSignedPart(line);
                    case LOOK_BOUNDARY:
                        // we should look for empty line first...?
                        return lookBoundary(line);
                    case STORE_PART:
                        if (line.contains(signedBoundary)) {
                            signedMap.put(signedBoundary, signedPartBuffer.toByteArray());
                            return LOOK_SIGNED_PART;
                        } else {
                            signedPartStream.write(byteLine);
                            return STORE_PART;
                            // TODO look for nested signature
                        }
                    case CONTINUE_CONTENT_TYPE:
                        if (EMPTY_LINE.matcher(line).lookingAt()
                                || NEW_HEADER.matcher(line).lookingAt()) {
                            return parseContentTypeHeader(MimeUtil.unfold(contentTypeBuffer.toString()));
                        } else {
                            contentTypeBuffer.append(line);
                            return CONTINUE_CONTENT_TYPE;
                        }
                    default:
                        throw new IllegalStateException();

                }
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("", e);
            } catch (IOException e) {
                throw new RuntimeException("", e);
            }
        }

        private static State parseContentTypeHeader(String line){
            boolean pgp = false;
            boolean multiPartSigned = false;
            String boundary = null;
            String parameters[] = line.substring(line.indexOf(":")+1).split(";");
            for (String param : parameters){
                if (param.contains("multipart/signed")) {
                    multiPartSigned = true;
                } else if (param.contains("application/pgp-signature")){
                    pgp = true;
                } else if (param.trim().startsWith("boundary")){
                    String quotedBoundary = param.substring(param.indexOf('=')+1).trim();
                    if (quotedBoundary.startsWith("\"")){
                        boundary = quotedBoundary.substring(1, quotedBoundary.length()-1);
                    } else {
                        boundary = quotedBoundary;
                    }
                }
            }
            if (pgp && multiPartSigned){
                signedBoundary = boundary;
                return LOOK_BOUNDARY;
            } else {
                return LOOK_SIGNED_PART;
            }
        }

        private State lookBoundary(String line){
            if (line.contains(signedBoundary)){
                signedPartBuffer = new ByteArrayOutputStream();
                signedPartStream = new EOLConvertingOutputStream(signedPartBuffer);
                return STORE_PART;
            } else {
                return LOOK_BOUNDARY;
            }
        }

        private static StringBuilder contentTypeBuffer;


        private State lookSignedPart(String line){
            if (CONTENT_TYPE.matcher(line).lookingAt()){
                contentTypeBuffer = new StringBuilder(line);
                return CONTINUE_CONTENT_TYPE;
            } else {
                return LOOK_SIGNED_PART;
            }
        }
    }
}
