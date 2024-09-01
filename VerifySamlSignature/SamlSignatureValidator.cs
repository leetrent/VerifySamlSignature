using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

public class SamlSignatureValidator
{
    public X509Certificate2 LoadCertificateFromMetadata(string certificateString)
    {
        // Load the X509Certificate from a base64-encoded string in the metadata
        byte[] certificateData = Convert.FromBase64String(certificateString);
        return new X509Certificate2(certificateData);
    }

    public X509Certificate2 LoadCertificateFromFile(string filePath)
    {
        // Load the certificate from the specified file path
        return new X509Certificate2(filePath);
    }

    public XmlDocument LoadSamlResponse(string samlResponseBase64)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;

        // Decode the Base64-encoded SAML response
        byte[] samlResponseBytes = Convert.FromBase64String(samlResponseBase64);
        string samlResponseXml = System.Text.Encoding.UTF8.GetString(samlResponseBytes);

        // Load the SAML response XML into an XmlDocument
        xmlDoc.LoadXml(samlResponseXml);
        return xmlDoc;
    }

    //public XmlDocument LoadSamlResponseFromFile(string filePath)
    //{
    //    // Read the SAML response from the file
    //    string samlResponseBase64 = File.ReadAllText(filePath);

    //    Console.WriteLine();
    //    Console.WriteLine(samlResponseBase64);
    //    Console.WriteLine();

    //    // Create an XmlDocument to hold the SAML response
    //    XmlDocument xmlDoc = new XmlDocument();
    //    xmlDoc.PreserveWhitespace = true;

    //    // Decode the Base64-encoded SAML response
    //    byte[] samlResponseBytes = Convert.FromBase64String(samlResponseBase64);
    //    string samlResponseXml = Encoding.UTF8.GetString(samlResponseBytes);

    //    // Load the SAML response XML into an XmlDocument
    //    xmlDoc.LoadXml(samlResponseXml);

    //    return xmlDoc;
    //}

    public XmlDocument LoadSamlResponseFromFile(string filePath)
    {
        // Read the SAML response XML directly from the file
        string samlResponseXml = File.ReadAllText(filePath);

        // Create an XmlDocument to hold the SAML response
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;

        // Load the SAML response XML into an XmlDocument
        xmlDoc.LoadXml(samlResponseXml);

        return xmlDoc;
    }

    //public bool VerifySamlSignature(XmlDocument samlResponseXml, X509Certificate2 certificate)
    //{
    //    // Create a SignedXml object
    //    SignedXml signedXml = new SignedXml(samlResponseXml);

    //    // Find the Signature node and load it into the SignedXml object
    //    XmlNodeList nodeList = samlResponseXml.GetElementsByTagName("Signature");
    //    if (nodeList.Count == 0)
    //    {
    //        throw new Exception("No Signature found in the SAML response.");
    //    }

    //    signedXml.LoadXml((XmlElement)nodeList[0]);

    //    // Verify the signature using the public key in the certificate
    //    return signedXml.CheckSignature(certificate, true);
    //}

    public bool VerifySamlSignature(XmlDocument samlResponseXml, X509Certificate2 certificate)
    {
        bool responseSignatureValid = false;
        bool assertionSignatureValid = false;

        // Create an XmlNamespaceManager to handle namespaces
        XmlNamespaceManager nsMgr = new XmlNamespaceManager(samlResponseXml.NameTable);
        nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        nsMgr.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        // Verify the signature on the Response element
        XmlElement responseSignatureElement = (XmlElement)samlResponseXml.SelectSingleNode("//ds:Signature", nsMgr);
        if (responseSignatureElement != null)
        {
            SignedXml signedXml = new SignedXml(samlResponseXml);
            signedXml.LoadXml(responseSignatureElement);
            responseSignatureValid = signedXml.CheckSignature(certificate, true);
        }
        else
        {
            Console.WriteLine("No Signature found in the Response element.");
        }

        // Verify the signature on the Assertion element
        XmlElement assertionElement = (XmlElement)samlResponseXml.SelectSingleNode("//saml2:Assertion", nsMgr);
        if (assertionElement != null)
        {
            SignedXml signedXml = new SignedXml(assertionElement);
            XmlElement assertionSignatureElement = (XmlElement)assertionElement.SelectSingleNode("//ds:Signature", nsMgr);
            if (assertionSignatureElement != null)
            {
                signedXml.LoadXml(assertionSignatureElement);
                assertionSignatureValid = signedXml.CheckSignature(certificate, true);
            }
            else
            {
                Console.WriteLine("No Signature found in the Assertion element.");
            }
        }

        // Both signatures should be valid
        return responseSignatureValid && assertionSignatureValid;
    }



}
