<?php
namespace Bill;

use Nticaric\Fiskalizacija\Bill\BillNumber;

class BillNumberTest extends \PHPUnit\Framework\TestCase
{
    public function testBillNumberClass()
    {
        $billNumber = new BillNumber("123456789", "POSL1", "12");
        $res = $billNumber->toXML();
        $this->assertStringEqualsFile('./tests/xml/business_bill_number.xml', $res);
    }
}
