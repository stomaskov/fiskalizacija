<?php namespace Nticaric\Fiskalizacija;

/**
 *
 * PHP API za fiskalizaciju računa
 *
 * @version 1.0
 * @author Nenad Tičarić <nticaric@gmail.com>
 * @project Fiskalizacija
 */

use DOMDocument;
use DOMElement;
use Exception;

class Fiskalizacija
{

    public $certificate;
    private $security;
    private $url = "https://cis.porezna-uprava.hr:8449/FiskalizacijaService";
    private $privateKeyResource;
    private $publicCertificateData;

    public function __construct($path, $pass, $security = 'SSL', $demo = false)
    {
        if ($demo == true) {
            $this->url = "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest";
        }
        $this->setCertificate($path, $pass);
        $this->privateKeyResource = openssl_pkey_get_private($this->certificate['pkey'], $pass);
        $this->publicCertificateData = openssl_x509_parse($this->certificate['cert']);
        $this->security = $security;
    }

    public function setCertificate($path, $pass)
    {
        try {
            $pkcs12 = $this->readCertificateFromDisk($path);
            openssl_pkcs12_read($pkcs12, $this->certificate, $pass);
        } catch (Exception $e) {
        }
    }

    public function readCertificateFromDisk($path): string
    {
        $cert = @file_get_contents($path);
        if (false === $cert) {
            throw new \Exception("Ne mogu procitati certifikat sa lokacije: " .
                $path, 1);
        }
        return $cert;
    }

    public function getPrivateKey()
    {
        return $this->certificate['pkey'];
    }

    public function signXML($XMLRequest)
    {
        $XMLRequestDOMDoc = new DOMDocument();
        $XMLRequestDOMDoc->loadXML($XMLRequest);

        $canonical = $XMLRequestDOMDoc->C14N();
        $DigestValue = base64_encode(hash('sha1', $canonical, true));

        $rootElem = $XMLRequestDOMDoc->documentElement;

        $SignatureNode = $rootElem->appendChild(new DOMElement('Signature'));
        $SignatureNode->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        $SignedInfoNode = $SignatureNode->appendChild(new DOMElement('SignedInfo'));
        $SignedInfoNode->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        $CanonicalizationMethodNode = $SignedInfoNode->appendChild(new DOMElement('CanonicalizationMethod'));
        $CanonicalizationMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

        $SignatureMethodNode = $SignedInfoNode->appendChild(new DOMElement('SignatureMethod'));
        $SignatureMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');

        $ReferenceNode = $SignedInfoNode->appendChild(new DOMElement('Reference'));
        $ReferenceNode->setAttribute('URI', sprintf('#%s', $XMLRequestDOMDoc->documentElement->getAttribute('Id')));

        $TransformsNode = $ReferenceNode->appendChild(new DOMElement('Transforms'));

        $Transform1Node = $TransformsNode->appendChild(new DOMElement('Transform'));
        $Transform1Node->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');

        $Transform2Node = $TransformsNode->appendChild(new DOMElement('Transform'));
        $Transform2Node->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

        $DigestMethodNode = $ReferenceNode->appendChild(new DOMElement('DigestMethod'));
        $DigestMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');

        $ReferenceNode->appendChild(new DOMElement('DigestValue', $DigestValue));

        $SignedInfoNode = $XMLRequestDOMDoc->getElementsByTagName('SignedInfo')->item(0);

        $X509Issuer = $this->publicCertificateData['issuer'];
        $X509IssuerName = sprintf(
            'OU=%s,O=%s,C=%s',
            $X509Issuer['OU'] ?? '',
            $X509Issuer['O'] ?? '',
            $X509Issuer['C'] ?? ''
        );
        $X509IssuerSerial = $this->publicCertificateData['serialNumber'];

        $publicCertificatePureString = str_replace('-----BEGIN CERTIFICATE-----', '', $this->certificate['cert']);
        $publicCertificatePureString = str_replace('-----END CERTIFICATE-----', '', $publicCertificatePureString);

        $signedInfoSignature = null;

        if (!openssl_sign($SignedInfoNode->C14N(true), $signedInfoSignature, $this->privateKeyResource, OPENSSL_ALGO_SHA1)) {
            throw new Exception('Unable to sign the request');
        }

        $SignatureNode = $XMLRequestDOMDoc->getElementsByTagName('Signature')->item(0);
        $SignatureValueNode = new DOMElement('SignatureValue', base64_encode($signedInfoSignature));
        $SignatureNode->appendChild($SignatureValueNode);

        $KeyInfoNode = $SignatureNode->appendChild(new DOMElement('KeyInfo'));

        $X509DataNode = $KeyInfoNode->appendChild(new DOMElement('X509Data'));
        $X509CertificateNode = new DOMElement('X509Certificate', $publicCertificatePureString);
        $X509DataNode->appendChild($X509CertificateNode);

        $X509IssuerSerialNode = $X509DataNode->appendChild(new DOMElement('X509IssuerSerial'));

        $X509IssuerNameNode = new DOMElement('X509IssuerName', $X509IssuerName);
        $X509IssuerSerialNode->appendChild($X509IssuerNameNode);

        $X509SerialNumberNode = new DOMElement('X509SerialNumber', $X509IssuerSerial);
        $X509IssuerSerialNode->appendChild($X509SerialNumberNode);

        return $this->createEnvelope($XMLRequestDOMDoc);
    }

    public function plainXML($XMLRequest)
    {
        $XMLRequestDOMDoc = new DOMDocument();
        $XMLRequestDOMDoc->loadXML($XMLRequest);

        return $this->createEnvelope($XMLRequestDOMDoc);
    }

    private function createEnvelope($XMLRequestDOMDoc)
    {
        $envelope = new DOMDocument();

        $envelope->loadXML('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
		    <soapenv:Body></soapenv:Body>
		</soapenv:Envelope>');

        $envelope->encoding = 'UTF-8';
        $envelope->xmlVersion = '1.0';
        $XMLRequestType = $XMLRequestDOMDoc->documentElement->localName;
        $XMLRequestTypeNode = $XMLRequestDOMDoc->getElementsByTagName($XMLRequestType)->item(0);
        $XMLRequestTypeNode = $envelope->importNode($XMLRequestTypeNode, true);

        $envelope->getElementsByTagName('Body')->item(0)->appendChild($XMLRequestTypeNode);
        return $envelope->saveXML();
    }

    public function sendSoap($payload): array
    {
        $ch = curl_init();

        $options = array(
            CURLOPT_URL => $this->url,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSL_VERIFYPEER => false,
            //CURLOPT_CAINFO => './tests/democacert.cer.pem',
        );

        switch ($this->security) {
            case 'SSL':
                break;
            case 'TLS':
                curl_setopt($ch, CURLOPT_SSLVERSION, 6);
                break;
            default:
                throw new \InvalidArgumentException(
                    'Treći parametar konstruktora klase Fiskalizacija mora biti SSL ili TLS!'
                );
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response) {
            curl_close($ch);
            return $this->parseResponse($response, $code);
        } else {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception($error);
        }

    }

    public function parseResponse($response, $code = 4): array
    {
        if ($code === 200) {
            $DOMResponse = new DOMDocument();
            $DOMResponse->loadXML($response);

            $uuid = $DOMResponse->getElementsByTagName('IdPoruke')->item(0)->nodeValue;
            $dateTime = $DOMResponse->getElementsByTagName('DatumVrijeme')->item(0)->nodeValue;
            $jir = $DOMResponse->getElementsByTagName('Jir')->item(0)->nodeValue;
            return [
                'header' => [
                    'uuid' => $uuid,
                    'dateTime' => $dateTime,
                ],
                'jir' => $jir
            ];
        } else {
            $DOMResponse = new DOMDocument();
            $DOMResponse->loadXML($response);

            $SifraGreske = $DOMResponse->getElementsByTagName('SifraGreske')->item(0);
            $PorukaGreske = $DOMResponse->getElementsByTagName('PorukaGreske')->item(0);

            if ($SifraGreske && $PorukaGreske) {
                throw new Exception(sprintf('%s: %s', $SifraGreske->nodeValue, $PorukaGreske->nodeValue));
            } else {
                throw new Exception(print_r($response, true), $code);
            }
        }

    }

    /**
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }
}
