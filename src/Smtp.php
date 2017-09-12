<?php 
namespace Cooker\mail;

class Smtp
{

    private $conn     = null;
    private $response = null;

    private $error    = '';

    const SMTP_MIME_CRLF = "\r\n";
    const DEBUG_LINE_LENGTH = 4098;

    protected $host = 'localhost';
    protected $port = '25';

    protected $user;
    protected $pass;

    public function connect($host = '', $port = '', $user = '', $pass = '')
    {
        $host = $host ?: $this->host; 
        $port = $port ?: $this->port;
        $user = $user ?: $this->user;
        $pass = $pass ?: $this->pass;

        $this->disconnect();

        $smtpHostUrl = parse_url($host);
        if(isset($smtpHostUrl['host']) && isset($smtpHostUrl['port'])){
            $host = $smtpHostUrl['host']; 
            $port = $smtpHostUrl['port'];
        }
        if(isset($smtpHostUrl['host']) && isset($smtpHostUrl['scheme'])){
            $host = sprintf('%s://%s', $smtpHostUrl['scheme'], $smtpHostUrl['host']); 
        }

        if(preg_match('/^tls:\/\//i', $host)){
            $host = preg_replace('/^tls:\/\//i', '', $host);
            $tls  = true;
        }
        $helloHost = GlobalVar::get('smtp_hello_host', 'localhost');
        $host      = Helper::idn_to_ascii($host);
        $this->conn = new Net_SMTP(
            $host
            , $port
            , $helloHost
            , false
            , GlobalVar::get('smtp_timeout', 0)
            , GlobalVar::get('smtp_conn_options')
        );

        if(GlobalVar::get('smtp_debug')){
            $this->conn->setDebug(array($this, 'debugHandler')); 
        }

        if(GlobalVar::get('smtp_auth_callback') && method_exists($this->conn, 'setAuthMethod')){
            foreach(GlobalVar('smtp_auth_callback') as $callback){
                $this->conn->setAuthMethod(
                    $callback['name']
                    , $callback['function']
                    , isset($callback['prepend']) ? $callback['prepend'] : true
                ); 
            }
        }
        $result = $this->conn->connect(GlobalVar::get('smtp_timeout'));
        if(!($result = $this->setResponse($result, 'Connection Failure'))){
            return $result;
        }
        if(method_exists($this->conn, 'setTimeoput') && ($timeout = ini_get('default_socket_timeout'))){
            $this->conn->setTimeout($timeout);
        }
        if($user && $pass){
            $user = strpos($user, '@') ? Helper::idn_to_ascii($user) : $user;        
            $authType = GlobalVar::get('smtp_auth_type', null);
            $result = $this->conn->auth($user, $pass, $authType, $tls);
        }
        return $this->setResponse($result, 'Authentication Failure');
    }




    public function send($from, $to, &$headers, &$body, $opts = array())
    {
        if(!is_object($this->conn)){
            return false;
        }      
        if(is_array($headers)){
            if(!$headerElements = $this->formatHeader($headers)){
                $this->reset();
                return false; 
            } 

        }
    }

    public function setResponse($response, $msg = '')
    {
        if(is_a($response, 'PEAR_Error')){
            $this->response[] = $msg . ': ' 
                . $response->getMessage() 
                . ' (Code: ' 
                . $response->getCode() . ')'; 
            $this->reset();
            $this->disconnect();
            return false;
        }
        return true;
    }

    public function reset()
    {
        if(is_object($this->conn)){
            $this->conn->rset();
        }
    }

    public function getResponse()
    {
        return (array)$this->response;
    }

    public function setHost($host)
    {
        $this->host = $host;
        return $this;
    }

    public function setPort($port)
    {
        $this->port = (int)$port;
        return $this;
    }

    public function setUser($user)
    {
        $this->user = $user;
        return $this;
    }

    public function setPassword($pass)
    {
        $this->pass = $pass;
        return $this;
    }

    public function disconnect()
    {
        if(is_object($this->conn)){
            $this->conn->disconnect();
            $this->conn = null;
        }

    }

    protected function formatHeader($headers)
    {
        $lines  = $received = array();
        $from   = null; 
        foreach($headers as $key => $value)
        {
            if(strcasecmp($key, 'From') === 0){
                $addresses = $this->parseRFC822($value); 
                $from = is_array($addresses) ? $addresses[0] : $from;
                if(strpos($from, ' ') !== false){
                    return false; 
                }
                $lines[] = $key . ': ' . $value;
            }elseif(strcasecmp($key, 'Received') === 0){
                if(is_array($value)){
                    foreach($value as $k => $v){
                        $received[] = $key . ': ' . $v; 
                    }
                }else{
                    $received[] = $key . ': ' . $value;
                } 
                $lines = array_merge($received, $lines);
            }else{
                if(is_array($value)){
                    $value = implode(', ', $value);
                } 
                $lines[] = $key . ': ' . $value;
            } 
        }
        return array($from, implode(self::SMTP_MIME_CRLF, $line) . self::SMTP_MIME_CRLF);
    }


    protected function parseRFC822($recipients) 
    {
        $recipients = implode(', ', (array)$recipients);    
        $addresses  = array();
        $recipients = preg_replace('/[\s\t]*\r?\n/', '', $recipients);
        $recipients = Helper::explode_quoted_string(',', $recipients);
        reset($recipients);
        foreach ($recipients as $recipient) {
            $a = Helper::explode_quoted_string(' ', $recipient);
            foreach ($a as $word) {
                $word = trim($word);
                $len  = strlen($word);
                if ($len && strpos($word, "@") > 0 && $word[$len-1] != '"') {
                    $word = preg_replace('/^<|>$/', '', $word);
                    if (!in_array($word, $addresses)) {
                        array_push($addresses, $word);
                    }
                }
            }
        }
        return $addresses;
    }
}
