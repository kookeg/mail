<?php 
namespace Cooker\Mail\Imap;

class Action
{
    protected $conn = null;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn; 
    }



}
