package util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public interface DataUtill {
	public static boolean verify(Document doc, X509Certificate cert) {
		try {
			if (!(doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength() > 0))
				throw new Exception("Cannot find Signature element");

			DOMValidateContext context = new DOMValidateContext(cert.getPublicKey(),
					doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
			XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);

			return signature.validate(context);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	static Document documentBuilder(String subject, String content) throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.newDocument();
	
		Element rootEl = doc.createElement("Email");
		doc.appendChild(rootEl);

		Attr subjectAtt = doc.createAttribute("subject");
		subjectAtt.setValue(subject);
		Attr contentAtt = doc.createAttribute("content");
		contentAtt.setValue(content);
		rootEl.setAttributeNode(subjectAtt);
		rootEl.setAttributeNode(contentAtt);
		
		return doc;
	}
	
	static byte[] signDataEnveloped(String subject, String content, PublicKey publicKey, PrivateKey privateKey)
			throws ParserConfigurationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			KeyException, MarshalException, XMLSignatureException, TransformerException {

		

		Document doc = documentBuilder(subject, content);

		

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer t = tf.newTransformer();

		DOMSource domSource = new DOMSource(doc);

		XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");

		Reference ref = xsf.newReference("", xsf.newDigestMethod(DigestMethod.SHA1, null),
				Collections.singletonList(xsf.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null,
				null);
		SignedInfo si = xsf.newSignedInfo(
				xsf.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null),
				xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

		DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());

		KeyInfoFactory kif = xsf.getKeyInfoFactory();

		KeyValue kv = kif.newKeyValue(publicKey);

		KeyInfo keyInfo = kif.newKeyInfo(Arrays.asList(kv));

		XMLSignature xmlSign = xsf.newXMLSignature(si, keyInfo);

		xmlSign.sign(dsc);

		DOMSource src = new DOMSource(doc);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		StreamResult res = new StreamResult(baos);
		t.transform(src, res);

		byte[] array = baos.toByteArray();

		return array;
	}

	static Document toXml(byte[] xml) throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
		return doc;
	}

}

