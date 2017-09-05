<?php 
namespace Cooker\Mail;

class Mail 
{
    private static $instance = null; 

    protected $imapServer = null;

    public static function getInstance()
    {
        if(is_null(self::$instance) || !(self::$instance instanceof self)){
            self::$instance = new self; 
        }
        return self::$instance;
    }

    public function imap($host, $port, $ssl = false)
    {
        $this->imapServer = new Imap($host, $port, $ssl);
        return $this->imapServer;
    }

    public function getImap()
    {
        return $this->imapServer;
    }

    private function __construct(){}

    private function __clone(){}
}
