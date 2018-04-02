/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - make sure that sessionId is always
 *                                                    initialized properly
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.*;

/**
 * When a client first connects to a server, it is required to send the
 * ClientHello as its first message. The client can also send a ClientHello in
 * response to a {@link HelloRequest} or on its own initiative in order to
 * re-negotiate the security parameters in an existing connection. See
 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.2">RFC 5246</a>.
 */
public final class ClientHello extends HandshakeMessage {

	// DTLS-specific constants ///////////////////////////////////////////

	private static final int VERSION_BITS = 8; // for major and minor each

	private static final int RANDOM_BYTES = 32;

	private static final int SESSION_ID_LENGTH_BITS = 8;

	private static final int COOKIE_LENGTH = 8;

	private static final int CIPHER_SUITS_LENGTH_BITS = 16;

	private static final int COMPRESSION_METHODS_LENGTH_BITS = 8;

	//新增加的常量，一个identity是两个字节
	private static final int IDENTITY_LIST_LENGTH_BITS = 8;

	private static final int IDENTITY_LENGTH_BITS = 16;

	private static final Charset CHAR_SET_UTF8 = Charset.forName("UTF8");

	// Members ///////////////////////////////////////////////////////////

	/**
	 * The version of the DTLS protocol by which the client wishes to
	 * communicate during this session.
	 */
	private ProtocolVersion clientVersion = new ProtocolVersion();

	/** A client-generated random structure. */
	private Random random;

	/** The ID of a session the client wishes to use for this connection. */
	private SessionId sessionId;

	/** The cookie used to prevent flooding attacks (potentially empty). */
	private byte[] cookie;

	/**
	 * This is a list of the cryptographic options supported by the client, with
	 * the client's first preference first.
	 */
	private List<CipherSuite> cipherSuites = new ArrayList<>();

	/**
	 * This is a list of the compression methods supported by the client, sorted
	 * by client preference.
	 */
	private List<CompressionMethod> compressionMethods = new ArrayList<>();

	/**
	 * Clients MAY request extended functionality from servers by sending data
	 * in the extensions field.
	 */
	private HelloExtensions extensions = new HelloExtensions();

	// Constructors ///////////////////////////////////////////////////////////

	/**
	 * Creates a <em>Client Hello</em> message to be sent to a server.
	 * 
	 * @param version
	 *            the protocol version to use
	 * @param secureRandom
	 *            a function to use for creating random values included in the
	 *            message
	 * @param supportedClientCertificateTypes
	 *            the list of certificate types supported by the client
	 * @param supportedServerCertificateTypes
	 *            the list of certificate types supported by the server
	 * @param peerAddress
	 *            the IP address and port of the peer this message has been
	 *            received from or should be sent to
	 */
	public ClientHello(ProtocolVersion version, SecureRandom secureRandom,
                       List<CertificateType> supportedClientCertificateTypes,
                       List<CertificateType> supportedServerCertificateTypes, InetSocketAddress peerAddress) {
		this(version, secureRandom, null, supportedClientCertificateTypes, supportedServerCertificateTypes, peerAddress);
	}

	/**
	 * Creates a <em>Client Hello</em> message to be used for resuming an existing
	 * DTLS session.
	 * 
	 * @param version
	 *            the protocol version to use
	 * @param secureRandom
	 *            a function to use for creating random values included in the message
	 * @param session
	 *            the (already existing) DTLS session to resume
	 * @param supportedClientCertificateTypes the list of certificate types supported by the client
	 * @param supportedServerCertificateTypes the list of certificate types supported by the server
	 */
	public ClientHello(ProtocolVersion version, SecureRandom secureRandom, DTLSSession session, List<CertificateType> supportedClientCertificateTypes,
                       List<CertificateType> supportedServerCertificateTypes) {
		this(version, secureRandom, session.getSessionIdentifier(), supportedClientCertificateTypes, supportedServerCertificateTypes, session.getPeer());
		addCipherSuite(session.getWriteState().getCipherSuite());
		addCompressionMethod(session.getWriteState().getCompressionMethod());
	}

	private ClientHello(ProtocolVersion version, SecureRandom secureRandom, SessionId sessionId, List<CertificateType> supportedClientCertificateTypes,
                        List<CertificateType> supportedServerCertificateTypes, InetSocketAddress peerAddress) {
		this(peerAddress);
		this.clientVersion = version;
		this.random = new Random(secureRandom);
		this.cookie = new byte[] {};
		if (sessionId != null) {
			this.sessionId = sessionId;
		} else {
			this.sessionId = SessionId.emptySessionId();
		}

		// the supported groups
		// TODO make list of supported groups configurable
		SupportedGroup[] supportedGroups = SupportedGroup.getPreferredGroups().toArray(new SupportedGroup[]{});
		this.extensions.addExtension(new SupportedEllipticCurvesExtension(supportedGroups));

		// the supported point formats
		List<ECPointFormat> formats = Arrays.asList(ECPointFormat.UNCOMPRESSED);
		this.extensions.addExtension(new SupportedPointFormatsExtension(formats));

		// the certificate types the client is able to provide to the server
		if (supportedClientCertificateTypes != null && !supportedClientCertificateTypes.isEmpty()) {
			CertificateTypeExtension clientCertificateType = new ClientCertificateTypeExtension(true);
			for (CertificateType certificateType : supportedClientCertificateTypes) {
				clientCertificateType.addCertificateType(certificateType);
			}
			this.extensions.addExtension(clientCertificateType);
		}

		// the type of certificates the client is able to process when provided
		// by the server
		if (supportedServerCertificateTypes != null && !supportedServerCertificateTypes.isEmpty()) {
			CertificateTypeExtension serverCertificateType = new ServerCertificateTypeExtension(true);
			for (CertificateType certificateType : supportedServerCertificateTypes) {
				serverCertificateType.addCertificateType(certificateType);
			}
			this.extensions.addExtension(serverCertificateType);
		}
	}

	private ClientHello(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {

		DatagramWriter writer = new DatagramWriter();

		writer.write(clientVersion.getMajor(), VERSION_BITS);
		writer.write(clientVersion.getMinor(), VERSION_BITS);

		writer.writeBytes(random.getRandomBytes());

		writer.write(sessionId.length(), SESSION_ID_LENGTH_BITS);
		writer.writeBytes(sessionId.getId());

		writer.write(cookie.length, COOKIE_LENGTH);
		writer.writeBytes(cookie);

		writer.write(cipherSuites.size() * 2, CIPHER_SUITS_LENGTH_BITS);
		writer.writeBytes(CipherSuite.listToByteArray(cipherSuites));

		//先把数组长度写进去
		writer.write(identityEncoded.size(), IDENTITY_LIST_LENGTH_BITS);
		//再循环遍历每个字符串序列化后的字节数组，写进去
		for (int i = 0; i < identityEncoded.size(); i++){
			//长度
			writer.write(identityEncoded.get(i).length, IDENTITY_LENGTH_BITS);
			//值
			writer.writeBytes(identityEncoded.get(i));
		}

		writer.write(compressionMethods.size(), COMPRESSION_METHODS_LENGTH_BITS);
		writer.writeBytes(CompressionMethod.listToByteArray(compressionMethods));

		if (extensions != null) {
			writer.writeBytes(extensions.toByteArray());
		}

		return writer.toByteArray();
	}

	/**
	 * Creates a new ClientObject instance from its byte representation.
	 * 
	 * @param byteArray
	 *            the bytes representing the message
	 * @param peerAddress
	 *            the IP address and port of the peer this message has been
	 *            received from or should be sent to
	 * @return the ClientHello object
	 * @throws HandshakeException
	 *             if any of the extensions included in the message is of an
	 *             unsupported type
	 */
	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress)
			throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		ClientHello result = new ClientHello(peerAddress);

		int major = reader.read(VERSION_BITS);
		int minor = reader.read(VERSION_BITS);
		result.clientVersion = new ProtocolVersion(major, minor);

		result.random = new Random(reader.readBytes(RANDOM_BYTES));

		int sessionIdLength = reader.read(SESSION_ID_LENGTH_BITS);
		result.sessionId = new SessionId(reader.readBytes(sessionIdLength));

		int cookieLength = reader.read(COOKIE_LENGTH);
		result.cookie = reader.readBytes(cookieLength);

		int cipherSuitesLength = reader.read(CIPHER_SUITS_LENGTH_BITS);
		result.cipherSuites = CipherSuite.listFromByteArray(reader.readBytes(cipherSuitesLength),
				cipherSuitesLength / 2); // 2

		//反序列化出我们需要的identity_list
		//先读出列表长度
		int identity_list_length = reader.read(IDENTITY_LIST_LENGTH_BITS);
		//循环遍历
		for(int i = 0; i < identity_list_length; i++){
			//读出identity长度
			int identity_length = reader.read(IDENTITY_LENGTH_BITS);
			byte[] tmp = reader.readBytes(identity_length);
			result.identityEncoded.add(tmp);
			result.identity_list.add(new String(tmp));
		}

		int compressionMethodsLength = reader.read(COMPRESSION_METHODS_LENGTH_BITS);
		result.compressionMethods = CompressionMethod.listFromByteArray(reader.readBytes(compressionMethodsLength),
				compressionMethodsLength);

		byte[] bytesLeft = reader.readBytesLeft();
		if (bytesLeft.length > 0) {
			result.extensions = HelloExtensions.fromByteArray(bytesLeft, peerAddress);
		}
		return result;

	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CLIENT_HELLO;
	}

	@Override
	public int getMessageLength() {

		// if no extensions set, empty; otherwise 2 bytes for field length and
		// then the length of the extensions. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.2
		int extensionsLength = (extensions == null || extensions.isEmpty()) ? 0 : (2 + extensions.getLength());

		// fixed sizes: version (2) + random (32) + session ID length (1) +
		// cookie length (1) + cipher suites length (2) + compression methods
		// length (1) +
		// Identity_List的长度 identity_list_length (1) = 40
		//变化的长度：identity_list_length个identity，每个的长度值是2个字节，还需要加上每个字节数组的长度
		int length = 40 + sessionId.length() + cookie.length + cipherSuites.size() * 2 + compressionMethods.size()
				+ extensionsLength ;
		for(int i = 0; i < identity_list.size(); i++){
			length += identityEncoded.get(i).length;
			length += 2;
		}
		return length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tVersion: ").append(clientVersion.getMajor()).append(", ").append(clientVersion.getMinor());
		sb.append(System.lineSeparator()).append("\t\tRandom:").append(System.lineSeparator()).append(random);
		sb.append("\t\tSession ID Length: ").append(sessionId.length());
		if (sessionId.length() > 0) {
			sb.append(System.lineSeparator()).append("\t\tSession ID: ").append(ByteArrayUtils.toHexString(sessionId.getId()));
		}
		sb.append(System.lineSeparator()).append("\t\tCookie Length: ").append(cookie.length);
		if (cookie.length > 0) {
			sb.append(System.lineSeparator()).append("\t\tCookie: ").append(ByteArrayUtils.toHexString(cookie));
		}
		sb.append(System.lineSeparator()).append("\t\tCipher Suites Length: ").append(cipherSuites.size() * 2);
		sb.append(System.lineSeparator()).append("\t\tCipher Suites (").append(cipherSuites.size()).append(" suites)");
		for (CipherSuite cipher : cipherSuites) {
			sb.append(System.lineSeparator()).append("\t\t\tCipher Suite: ").append(cipher);
		}
		sb.append(System.lineSeparator()).append("\t\tCompression Methods Length: ").append(compressionMethods.size());
		sb.append(System.lineSeparator()).append("\t\tCompression Methods (").append(compressionMethods.size()).append(" method)");
		for (CompressionMethod method : compressionMethods) {
			sb.append(System.lineSeparator()).append("\t\t\tCompression Method: ").append(method);
		}
		if (extensions != null) {
			sb.append(System.lineSeparator()).append(extensions);
		}

		return sb.toString();
	}

	// Getters and Setters ////////////////////////////////////////////

	public ProtocolVersion getClientVersion() {
		return clientVersion;
	}

	public Random getRandom() {
		return random;
	}

	public SessionId getSessionId() {
		return sessionId;
	}

	/**
	 * Checks whether this message contains a session ID.
	 * 
	 * @return <code>true</code> if the message contains a non-null session ID with length &gt; 0
	 */
	public boolean hasSessionId() {
		return sessionId != null && sessionId.length() > 0;
	}

	void setSessionId(SessionId sessionId) {
		this.sessionId = sessionId;
	}

	public byte[] getCookie() {
		return cookie;
	}

	public void setCookie(byte[] cookie) {
		this.cookie = Arrays.copyOf(cookie, cookie.length);
	}

	public List<CipherSuite> getCipherSuites() {
		return Collections.unmodifiableList(cipherSuites);
	}

	public void addCipherSuite(CipherSuite cipherSuite) {
		if (cipherSuites == null) {
			cipherSuites = new ArrayList<CipherSuite>();
		}
		System.out.println("添加加密算法"+cipherSuites);
		cipherSuites.add(cipherSuite);
	}

	public List<CompressionMethod> getCompressionMethods() {
		return Collections.unmodifiableList(compressionMethods);
	}

	public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
		this.compressionMethods.addAll(compressionMethods);
	}

	public void addCompressionMethod(CompressionMethod compressionMethod) {
		if (compressionMethods == null) {
			compressionMethods = new ArrayList<CompressionMethod>();
		}
		compressionMethods.add(compressionMethod);
	}

	void addExtension(HelloExtension extension) {
		if (extensions != null) {
			extensions.addExtension(extension);
		}
	}

	/**
	 * Gets the supported elliptic curves.
	 * 
	 * @return the client's supported elliptic curves extension if available,
	 *         otherwise <code>null</code>.
	 */
	public SupportedEllipticCurvesExtension getSupportedEllipticCurvesExtension() {
		if (extensions != null) {
			return (SupportedEllipticCurvesExtension) extensions.getExtension(ExtensionType.ELLIPTIC_CURVES);
		} else {
			return null;
		}
	}

	/**
	 * 
	 * @return the client's certificate type extension if available, otherwise
	 *         <code>null</code>.
	 */
	public ClientCertificateTypeExtension getClientCertificateTypeExtension() {
		if (extensions != null) {
			return (ClientCertificateTypeExtension) extensions.getExtension(ExtensionType.CLIENT_CERT_TYPE);
		} else {
			return null;
		}
	}

	/**
	 * 
	 * @return the client's certificate type extension if available, otherwise
	 *         <code>null</code>.
	 */
	public ServerCertificateTypeExtension getServerCertificateTypeExtension() {
		if (extensions != null) {
			return (ServerCertificateTypeExtension) extensions.getExtension(ExtensionType.SERVER_CERT_TYPE);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>MaximumFragmentLength</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>MaximumFragmentLength</em> extension.
	 */
	public MaxFragmentLengthExtension getMaxFragmentLengthExtension() {
		if (extensions != null) {
			return (MaxFragmentLengthExtension) extensions.getExtension(ExtensionType.MAX_FRAGMENT_LENGTH);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>Server Name Indication</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>Server Name Indication</em> extension.
	 */
	public ServerNameExtension getServerNameExtension() {
		if (extensions != null) {
			return (ServerNameExtension) extensions.getExtension(ExtensionType.SERVER_NAME);
		} else {
			return null;
		}
	}

	/**
	 * 我的扩展
	 */

	/*添加一个存放Identity的字符串数组*/
	private List<String> identity_list = new ArrayList<>();

	/*添加一个存放Identity序列化以后的数组*/
	private List<byte[]> identityEncoded = new ArrayList<>();

	public List<String> getIdentity_list() {
		return identity_list;
	}

	public void addIdentityTolist(String identity) {
		identity_list.add(identity);
		identityEncoded.add(identity.getBytes(CHAR_SET_UTF8));
	}

	public List<byte[]> getIdentityEncoded() {
		return identityEncoded;
	}

	public void addIdentityEncodedToList(byte[] identityEncodedArray) {
		identityEncoded.add(identityEncodedArray);
	}

}
