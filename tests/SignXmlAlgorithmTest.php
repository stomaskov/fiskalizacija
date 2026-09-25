<?php

use Nticaric\Fiskalizacija\Fiskalizacija;

/**
 * From 2027-01-01 the tax authority's production CIS rejects request messages signed with
 * RSA-SHA1 (error s004) — see "Fiskalizacija - Tehnicka specifikacija za korisnike" v2.7,
 * the message-signing section under §9/§8.7. signXML() must use RSA-SHA256 for both the
 * digest and the signature.
 */
class SignXmlAlgorithmTest extends \PHPUnit\Framework\TestCase
{
    private const SIGNATURE_METHOD_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const DIGEST_METHOD_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    private string $certificatePath = '';
    private string $privateKeyPem = '';

    protected function tearDown(): void
    {
        if ($this->certificatePath !== '' && file_exists($this->certificatePath)) {
            unlink($this->certificatePath);
        }
    }

    public function testTheSignatureMethodIsRsaSha256(): void
    {
        [, $signed] = $this->signMinimalRequest();

        $method = $signed->getElementsByTagName('SignatureMethod')->item(0);

        $this->assertSame(self::SIGNATURE_METHOD_SHA256, $method->getAttribute('Algorithm'));
    }

    public function testTheDigestMethodIsSha256(): void
    {
        [, $signed] = $this->signMinimalRequest();

        $method = $signed->getElementsByTagName('DigestMethod')->item(0);

        $this->assertSame(self::DIGEST_METHOD_SHA256, $method->getAttribute('Algorithm'));
    }

    /**
     * Recomputes the digest exactly as signXML() must: base64(sha256(c14n(original request))).
     * If the implementation still hashes with SHA1, this value will not match.
     */
    public function testTheDigestValueIsTheSha256OfTheCanonicalisedRequest(): void
    {
        $originalXml = '<RacunZahtjev Id="test-id"><Foo>bar</Foo></RacunZahtjev>';

        [, $signed] = $this->signMinimalRequest($originalXml);

        $original = new DOMDocument();
        $original->loadXML($originalXml);
        $expectedDigest = base64_encode(hash('sha256', $original->C14N(), true));

        $actualDigest = $signed->getElementsByTagName('DigestValue')->item(0)->textContent;

        $this->assertSame($expectedDigest, $actualDigest);
    }

    /**
     * Proves the SignatureValue is a genuine RSA-SHA256 signature over the SignedInfo block
     * (not merely labelled as one): re-signing the same, already-produced SignedInfo with our
     * own copy of the private key and SHA256 must reproduce byte-for-byte the value signXML()
     * emitted.
     */
    public function testTheSignatureValueIsAGenuineRsaSha256Signature(): void
    {
        [, $signed] = $this->signMinimalRequest();

        $signedInfo = $signed->getElementsByTagName('SignedInfo')->item(0);

        $expectedSignature = null;
        openssl_sign($signedInfo->C14N(true), $expectedSignature, $this->privateKeyPem, OPENSSL_ALGO_SHA256);

        $actualSignature = base64_decode(
            $signed->getElementsByTagName('SignatureValue')->item(0)->textContent
        );

        $this->assertSame($expectedSignature, $actualSignature);
    }

    /** @return array{0: Fiskalizacija, 1: DOMDocument} */
    private function signMinimalRequest(
        string $xml = '<RacunZahtjev Id="test-id"><Foo>bar</Foo></RacunZahtjev>'
    ): array {
        $fis = $this->fiskalizacija();

        $signedXml = $fis->signXML($xml);

        $signed = new DOMDocument();
        $signed->loadXML($signedXml);

        return [$fis, $signed];
    }

    private function fiskalizacija(): Fiskalizacija
    {
        $this->certificatePath = $this->writeCertificate('secret');

        return new Fiskalizacija($this->certificatePath, 'secret', 'TLS', false);
    }

    /** A throwaway self-signed PKCS#12, so no real certificate is needed to construct. */
    private function writeCertificate(string $password): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $this->privateKeyPem);

        $csr = openssl_csr_new(
            ['countryName' => 'HR', 'organizationName' => 'Test', 'commonName' => 'test.example'],
            $key
        );
        $cert = openssl_csr_sign($csr, null, $key, 365);

        openssl_pkcs12_export($cert, $pkcs12, $key, $password);

        $path = tempnam(sys_get_temp_dir(), 'fiskal') . '.p12';
        file_put_contents($path, $pkcs12);

        return $path;
    }
}
