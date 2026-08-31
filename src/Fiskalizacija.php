<?php

namespace Nticaric\Fiskalizacija;

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
use InvalidArgumentException;
use OpenSSLAsymmetricKey;

class Fiskalizacija
{
    /**
     * Seconds allowed for the whole CIS round trip.
     *
     * Was 5, which is the dangerous kind of too-short: when it fires on a reply that is
     * already on the wire, CIS has recorded the receipt and issued a JIR that the caller
     * never receives. The caller then re-sends the same receipt number and CIS issues a
     * second JIR for it. Give the service room to answer instead.
     */
    public const DEFAULT_TIMEOUT = 30;

    /** Seconds allowed to establish the connection. Failing to connect is cheap to retry. */
    public const DEFAULT_CONNECT_TIMEOUT = 10;

    public array $certificate;
    private string $security;
    private string $url = "https://cis.porezna-uprava.hr:8449/FiskalizacijaService";
    private OpenSSLAsymmetricKey|false $privateKeyResource;
    private array|false $publicCertificateData;
    private int $timeout = self::DEFAULT_TIMEOUT;
    private int $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT;

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
        $certificate = [];
        $pkcs12 = $this->readCertificateFromDisk($path);
        openssl_pkcs12_read($pkcs12, $certificate, $pass);
        $this->certificate = $certificate;
    }

    public function readCertificateFromDisk($path)
    {
        $cert = @file_get_contents($path);
        if (false === $cert) {
            throw new Exception("Ne mogu procitati certifikat sa lokacije: " .
                $path, 1);
        }
        return $cert;
    }

    public function getPrivateKey()
    {
        return $this->certificate['pkey'];
    }

    public function signXML($XMLRequest): bool|string
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
        if (isset($X509Issuer['OU'])) {
            $X509IssuerName = sprintf('OU=%s,O=%s,C=%s', $X509Issuer['OU'], $X509Issuer['O'], $X509Issuer['C']);
        } elseif (isset($X509Issuer['CN'])) {
            $X509IssuerName = sprintf('O=%s,C=%s,CN=%s', $X509Issuer['O'], $X509Issuer['C'], $X509Issuer['CN']);
        } else {
            $X509IssuerName = sprintf('OU=%s,O=%s,C=%s', $X509Issuer['OU'], $X509Issuer['O'], $X509Issuer['C']);
        }
        $X509IssuerSerial = $this->publicCertificateData['serialNumber'];

        $publicCertificatePureString = str_replace('-----BEGIN CERTIFICATE-----', '', $this->certificate['cert']);
        $publicCertificatePureString = str_replace('-----END CERTIFICATE-----', '', $publicCertificatePureString);

        $this->signedInfoSignature = null;
        $signedInfoSignature = null;

        if (!openssl_sign($SignedInfoNode->C14N(true), $signedInfoSignature, $this->privateKeyResource, OPENSSL_ALGO_SHA1)) {
            throw new Exception('Unable to sign the request');
        }
        $this->signedInfoSignature = $signedInfoSignature;

        $SignatureNode = $XMLRequestDOMDoc->getElementsByTagName('Signature')->item(0);
        $SignatureValueNode = new DOMElement('SignatureValue', base64_encode($this->signedInfoSignature));
        $SignatureNode->appendChild($SignatureValueNode);

        $KeyInfoNode = $SignatureNode->appendChild(new DOMElement('KeyInfo'));

        $X509DataNode = $KeyInfoNode->appendChild(new DOMElement('X509Data'));
        $X509CertificateNode = new DOMElement('X509Certificate', $publicCertificatePureString);
        $X509DataNode->appendChild($X509CertificateNode);

        $X509IssuerSerialNode = $X509DataNode->appendChild(new DOMElement('X509IssuerSerial'));

        $X509IssuerNameNode = new DOMElement('X509IssuerName', $X509IssuerName);
        $X509IssuerSerialNode->appendChild($X509IssuerNameNode);

        // X509SerialNumber integer overflow fix
        if (str_starts_with($X509IssuerSerial, '0x')) {
            $hex = substr($X509IssuerSerial, 2);
            $newX509IssuerSerial = '';
            $len = strlen($hex);
            for ($i = 1; $i <= $len; $i++) {
                $newX509IssuerSerial = bcadd($newX509IssuerSerial, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
            }
            $X509IssuerSerial = $newX509IssuerSerial;
        }
        $X509SerialNumberNode = new DOMElement('X509SerialNumber', $X509IssuerSerial);
        $X509IssuerSerialNode->appendChild($X509SerialNumberNode);

        $envelope = new DOMDocument();

        $envelope->loadXML('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
		    <soapenv:Body></soapenv:Body>
		</soapenv:Envelope>');

        $envelope->encoding = 'UTF-8';
        $envelope->version = '1.0';
        $XMLRequestType = $XMLRequestDOMDoc->documentElement->localName;
        $XMLRequestTypeNode = $XMLRequestDOMDoc->getElementsByTagName($XMLRequestType)->item(0);
        $XMLRequestTypeNode = $envelope->importNode($XMLRequestTypeNode, true);

        $envelope->getElementsByTagName('Body')->item(0)->appendChild($XMLRequestTypeNode);
        return $envelope->saveXML();
    }

    public function plainXML($XMLRequest)
    {
        $XMLRequestDOMDoc = new DOMDocument();
        $XMLRequestDOMDoc->loadXML($XMLRequest);

        $envelope = new DOMDocument();

        $envelope->loadXML('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
		    <soapenv:Body></soapenv:Body>
		</soapenv:Envelope>');

        $envelope->encoding = 'UTF-8';
        $envelope->version = '1.0';
        $XMLRequestType = $XMLRequestDOMDoc->documentElement->localName;
        $XMLRequestTypeNode = $XMLRequestDOMDoc->getElementsByTagName($XMLRequestType)->item(0);
        $XMLRequestTypeNode = $envelope->importNode($XMLRequestTypeNode, true);

        $envelope->getElementsByTagName('Body')->item(0)->appendChild($XMLRequestTypeNode);
        return $envelope->saveXML();
    }

    /**
     * Override the CIS timeouts, in seconds. Callers run under their own schedules and
     * lock windows, so this is tunable without a package release.
     */
    public function setTimeouts(int $timeout, ?int $connectTimeout = null): void
    {
        $this->timeout = $timeout;

        if ($connectTimeout !== null) {
            $this->connectTimeout = $connectTimeout;
        }
    }

    /**
     * The curl options for one CIS request. Separate from sendSoap() so the transport
     * settings can be asserted without making a network call.
     */
    public function curlOptions($payload): array
    {
        return array(
            CURLOPT_URL => $this->url,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSL_VERIFYPEER => false,
            //CURLOPT_CAINFO => './tests/democacert.cer.pem',
        );
    }

    public function sendSoap($payload)
    {
        $ch = curl_init();

        $options = $this->curlOptions($payload);

        switch ($this->security) {
            case 'SSL':
                break;
            case 'TLS':
                curl_setopt($ch, CURLOPT_SSLVERSION, 6);
                break;
            default:
                throw new InvalidArgumentException(
                    'Treći parametar konstruktora klase Fiskalizacija mora biti SSL ili TLS!'
                );
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response) {
            curl_close($ch);
            return $this->parseResponse($response, $code);
        }

        // Typed, and carrying the curl error code, so the caller can tell a request that
        // provably never reached CIS from one that may have been accepted before the
        // connection failed. Re-sending the latter is what mints a second JIR for one
        // receipt. curl_error()/curl_errno() must both be read before curl_close().
        $error = curl_error($ch);
        $errno = curl_errno($ch);
        curl_close($ch);

        throw new TransportException($error, $errno);
    }

    public function parseResponse($response, $code = 4)
    {
        $DOMResponse = new DOMDocument();
        $DOMResponse->loadXML($response);
        if ($code === 200) {

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

            $SifraGreske = $DOMResponse->getElementsByTagName('SifraGreske')->item(0);
            $PorukaGreske = $DOMResponse->getElementsByTagName('PorukaGreske')->item(0);

            if ($SifraGreske && $PorukaGreske) {
                throw new Exception(sprintf('%s: %s', $SifraGreske->nodeValue, $PorukaGreske->nodeValue));
            } else {
                throw new Exception(print_r($response, true), $code);
            }
        }

    }

    public function getUrl()
    {
        return $this->url;
    }
}
