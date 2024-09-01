using System.Security.Cryptography.X509Certificates;
using System.Xml;

class Program
{
    static void Main()
    {
        //string samlResponseBase64 = "Your Base64 encoded SAML Response"; // Replace with actual SAML response
        //string certificateString = "Your Base64 encoded X509Certificate from metadata"; // Replace with actual certificate string

        string certificateFromMetadataFile = "C:\\Users\\Lee\\Dev\\Learning\\Repo\\VerifySamlSignature\\VerifySamlSignature\\CertificateFromMetadata.txt";
        string samlResponseFromFile = "C:\\Users\\Lee\\Dev\\Learning\\Repo\\VerifySamlSignature\\VerifySamlSignature\\saml_response.xml";

        // Step 1: Load the certificate from the metadata
        SamlSignatureValidator validator = new SamlSignatureValidator();
        //X509Certificate2 certificate = validator.LoadCertificateFromMetadata(certificateString);

        X509Certificate2 certificate = validator.LoadCertificateFromFile(certificateFromMetadataFile);

        // Step 2: Load the SAML response
        //XmlDocument samlResponseXml = validator.LoadSamlResponse(samlResponseBase64);
        //XmlDocument samlResponseXml = validator.LoadSamlResponse(samlResponseBase64);
        XmlDocument samlResponseXml = validator.LoadSamlResponseFromFile(samlResponseFromFile);

        // Step 3: Verify the SAML signature
        bool isValid = validator.VerifySamlSignature(samlResponseXml, certificate);

        if (isValid)
        {
            Console.WriteLine("The SAML response signature is valid.");
        }
        else
        {
            Console.WriteLine("The SAML response signature is NOT valid.");
        }
    }
}
