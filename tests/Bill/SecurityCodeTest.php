<?php
namespace Bill;

use Nticaric\Fiskalizacija\Bill\Bill;

/**
 * Pins the ZKI (zaštitni kod izdavatelja) against the Tax Administration's own definition
 * in "Fiskalizacija — Tehnička specifikacija za korisnike", §12.1:
 *
 *     medjurezultat = oib + datVrijeme + brOznRac + oznPosPr + oznNapUr + iznosUkupno
 *
 * The concatenation order is the whole of the algorithm. CIS copies the ZKI out of the
 * request rather than recomputing it, so a wrong order is accepted silently and only shows
 * up when someone verifies a receipt — which is why this needs a test rather than trust.
 */
class SecurityCodeTest extends \PHPUnit\Framework\TestCase
{
    private const OIB   = '32314900695';
    private const DT    = '15.07.2014 20:11:15';
    private const BOR   = '123';
    private const OPP   = 'POSL1';
    private const ONU   = '456';
    private const TOTAL = '456.10';

    /**
     * The operands are deliberately all distinct and non-numeric-looking where possible:
     * with bor/opp transposed the concatenation still produces a valid-looking 32-char
     * hash, so only comparing against an independently built payload catches it.
     */
    public function testSecurityCodeSignsTheOperandsInSpecOrder()
    {
        $privateKey = $this->privateKey();

        $actual = (new Bill())->securityCode(
            $privateKey,
            self::OIB,
            self::DT,
            self::BOR,
            self::OPP,
            self::ONU,
            self::TOTAL
        );

        $this->assertSame($this->expectedZki($privateKey), $actual);
    }

    /**
     * Guards the specific defect: swapping the business-area and receipt-number operands
     * must produce a different code. Without this, an implementation that concatenated
     * opp before bor would still pass a test that only checked the hash's shape.
     */
    public function testTransposingTheReceiptNumberAndBusinessAreaChangesTheCode()
    {
        $privateKey = $this->privateKey();

        $correct = (new Bill())->securityCode(
            $privateKey,
            self::OIB,
            self::DT,
            self::BOR,
            self::OPP,
            self::ONU,
            self::TOTAL
        );

        $transposed = (new Bill())->securityCode(
            $privateKey,
            self::OIB,
            self::DT,
            self::OPP,
            self::BOR,
            self::ONU,
            self::TOTAL
        );

        $this->assertNotSame($correct, $transposed);
    }

    public function testSecurityCodeIsAThirtyTwoCharacterHexDigest()
    {
        $actual = (new Bill())->securityCode(
            $this->privateKey(),
            self::OIB,
            self::DT,
            self::BOR,
            self::OPP,
            self::ONU,
            self::TOTAL
        );

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $actual);
    }

    /** RSA-SHA256 over the §12.1 payload, MD5 of the raw signature. */
    private function expectedZki(string $privateKey): string
    {
        $payload = self::OIB . self::DT . self::BOR . self::OPP . self::ONU . self::TOTAL;

        $signature = null;
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return md5($signature);
    }

    private function privateKey(): string
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $pem);

        return $pem;
    }
}
