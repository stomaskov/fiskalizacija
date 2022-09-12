<?php
namespace Bill;

use Nticaric\Fiskalizacija\Bill\Refund;

class RefundTest extends \PHPUnit\Framework\TestCase
{
    public function testRefundClass()
    {
        $refund = new Refund("Povratna naknada", 1.23);
        $res = $refund->toXML();
        $this->assertStringEqualsFile('./tests/xml/business_refund.xml', $res);
    }
}
