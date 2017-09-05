<?php 
namespace Cooker\Mail\Imap;

use Cooker\Mail\Helper;
use Cooker\Mail\GlobalVar;
use Cooker\Mail\Error;
use Cooker\Mail\Exception\ImapException;


class Connection
{
    protected $fp = null;

    protected $errno  = 0;

    protected $errstr = '';

    protected $data   = array();

    protected $cmdNum = 0;

    protected $cmdTag;

    protected $capability = array();



    const DEBUG_LINE_LENGTH = 4098; // 4KB + 2B for \r\n

    public function connect($host, $port, $user, $password, $options = array())
    {
        if(!$this->_connect($host)){
            return false; 
        }
        if(GlobalVar::get('imap_ident') && $this->getCapability('ID')){
            $this->data['ID'] = $this->commandID(GlobalVar::get('imap_ident')); 
        }
        $authMethod  = GlobalVar::get('imap_auth_type');
        $authMethods = array();
        if($authMethod == 'CHECK'){
            if($capability = $this->getCapability('AUTH')){
                $authMethods = $capability; 
            } 
            $loginDisabled = $this->getCapability('LOGINDISABLED');
            if($authMethods && ($key = array_search("LOGIN", $authMethods)) !== false){
                if($loginDisabled){
                    unset($authMethods[$key]);
                } 
            }elseif(!$loginDisabled){
                $authMethods[] = "LOGIN"; 
            }
            $allMethods = array('DIGEST-MD5', 'CRAM-MD5', 'CRAM_MD5', 'PLAIN', 'LOGIN');
            foreach($allMethods as $method){
                if(in_array($method, $authMethods)){
                    $authMethod = $method;
                    break;
                } 
            }
        }else{
            if($authMethod == 'LOGIN' && $this->getCapability('LOGINDISABLED')){
                throw new ImapException('Logined disabled by IMAP Server');
            }
            if($authMethod == 'AUTH'){
                $authMethod = 'CRAM-MD5';
            }
        
        }
        switch($authMethod){
            case 'CRAM-MD5':
            case 'DIGEST-MD5': 
            case 'GSSAPI':
            case 'PLAIN':
                $result = $this->authenticate($user, $password, $authMethod);
                break;
            case 'LOGIN':
                $result = $this->login($user, $password);
                break;
            default:
                $this->setError(Error::ERROR_BAD, "Configuration error. Unknown auth method: $authMethod");
        }
        if(isset($result) && is_resource($result)){
            if(GlobalVar::get('imap_force_caps')){
                $this->clearCapability();
            } 
            return true;
        }
        return false;
    }


    /**
     * LOGIN Authentication
     *
     * @access protected
     * @param string $user Username
     * @param string $pass Password
     *
     * @return resource Connection resourse on success, error code on error
     */

    protected function login($user, $password)
    {
        if ($this->getCapability('LOGINDISABLED')) {
            $this->setError(Error::ERROR_BAD, "Login disabled by IMAP server");
            return false;
        }

        list($code, $response) = $this->execute(
            'LOGIN'
            , array(Helper::escape($user), Helper::escape($password))
            , Command::COMMAND_CAPABILITY | Command::COMMAND_ANONYMIZED
        );

        // re-set capabilities list if untagged CAPABILITY response provided
        if (preg_match('/\* CAPABILITY (.+)/i', $response, $matches) && isset($matches[1])) {
            $this->parseCapability($matches[1], true);
        }
        if ($code == Error::ERROR_OK) {
            return $this->fp;
        }
        return $code;  
    }

    /**
     * DIGEST-MD5/CRAM-MD5/PLAIN Authentication
     *
     * @access protected
     * @param string $user Username
     * @param string $pass Password
     * @param string $type Authentication type (PLAIN/CRAM-MD5/DIGEST-MD5)
     * @return resource Connection resourse on success, error code on error
     */

    protected function authenticate($user, $pass, $type = 'PLAIN')
    {
        if ($type == 'CRAM-MD5' || $type == 'DIGEST-MD5') {
            if ($type == 'DIGEST-MD5' && !class_exists('Auth_SASL')) {
                $this->setError(Error::ERROR_BYE,
                    "The Auth_SASL package is required for DIGEST-MD5 authentication");
                return Error::ERROR_BAD;
            }

            $this->putLine($this->nextTag() . " AUTHENTICATE $type");
            $line = trim($this->readReply());

            if (isset($line[0]) && $line[0] == '+') {
                $challenge = substr($line, 2);
            }
            else {
                return $this->parseResult($line);
            }

            if ($type == 'CRAM-MD5') {
                // RFC2195: CRAM-MD5
                $ipad = '';
                $opad = '';
                $xor  = function($str1, $str2) {
                    $result = '';
                    $size   = strlen($str1);
                    for ($i=0; $i<$size; $i++) {
                        $result .= chr(ord($str1[$i]) ^ ord($str2[$i]));
                    }
                    return $result;
                };

                // initialize ipad, opad
                for ($i=0; $i<64; $i++) {
                    $ipad .= chr(0x36);
                    $opad .= chr(0x5C);
                }

                // pad $pass so it's 64 bytes
                $pass = str_pad($pass, 64, chr(0));

                // generate hash
                $hash  = md5($xor($pass, $opad) . pack("H*", md5($xor($pass, $ipad) . base64_decode($challenge))));
                $reply = base64_encode($user . ' ' . $hash);

                // send result
                $this->putLine($reply, true, true);
            }
            else {
                // RFC2831: DIGEST-MD5
                // proxy authorization
                if (GlobalVar::get('imap_auth_cid')){
                    $authc = GlobalVar::get('imap_auth_cid');
                    $pass  = GlobalVar::get('imap_auth_pw');
                }
                else {
                    $authc = $user;
                    $user  = '';
                }

                $auth_sasl = new Auth_SASL;
                $auth_sasl = $auth_sasl->factory('digestmd5');
                $reply     = base64_encode($auth_sasl->getResponse($authc, $pass,
                    base64_decode($challenge), $this->host, 'imap', $user));

                // send result
                $this->putLine($reply, true, true);
                $line = trim($this->readReply());

                if ($line[0] != '+') {
                    return $this->parseResult($line);
                }

                // check response
                $challenge = substr($line, 2);
                $challenge = base64_decode($challenge);
                if (strpos($challenge, 'rspauth=') === false) {
                    $this->setError(Error::ERROR_BAD,
                        "Unexpected response from server to DIGEST-MD5 response");
                    return Error::ERROR_BAD;
                }

                $this->putLine('');
            }

            $line   = $this->readReply();
            $result = $this->parseResult($line);
        }
        else if ($type == 'GSSAPI') {
            if (!extension_loaded('krb5')) {
                $this->setError(Error::ERROR_BYE,
                    "The krb5 extension is required for GSSAPI authentication");
                return Error::ERROR_BAD;
            }

            if (!GlobalVar::get('gssapi_cn')) {
                $this->setError(Error::ERROR_BYE,
                    "The gssapi_cn parameter is required for GSSAPI authentication");
                return Error::ERROR_BAD;
            }

            if (!GlobalVar::get('gssapi_context')) {
                $this->setError(Error::ERROR_BYE,
                    "The gssapi_context parameter is required for GSSAPI authentication");
                return Error::ERROR_BAD;
            }

            putenv('KRB5CCNAME=' . GlobalVar::get('imap_gssapi_cn'));

            try {
                $ccache = new KRB5CCache();
                $ccache->open(GlobalVar::get('imap_gssapi_cn'));
                $gssapicontext = new GSSAPIContext();
                $gssapicontext->acquireCredentials($ccache);

                $token   = '';
                $success = $gssapicontext->initSecContext(GlobalVar::get('imap_gssapi_context'), null, null, null, $token);
                $token   = base64_encode($token);
            }
            catch (Exception $e) {
                $this->setError(Error::ERROR_BYE, "GSSAPI authentication failed");
                return Error::ERROR_BAD;
            }

            $this->putLine($this->nextTag() . " AUTHENTICATE GSSAPI " . $token);
            $line = trim($this->readReply());

            if ($line[0] != '+') {
                return $this->parseResult($line);
            }

            try {
                $challenge = base64_decode(substr($line, 2));
                $gssapicontext->unwrap($challenge, $challenge);
                $gssapicontext->wrap($challenge, $challenge, true);
            }
            catch (Exception $e) {
                $this->setError(Error::ERROR_BYE, "GSSAPI authentication failed");
                return Error::ERROR_BAD;
            }

            $this->putLine(base64_encode($challenge));

            $line   = $this->readReply();
            $result = $this->parseResult($line);
        }else{
            // proxy authorization
            if (GlobalVar::get('imap_auth_cid')) {
                $authc = GlobalVar::get('imap_auth_cid');
                $pass  = GlobalVar::get('imap_auth_pw');
            }
            else {
                $authc = $user;
                $user  = '';
            }

            $reply = base64_encode($user . chr(0) . $authc . chr(0) . $pass);

            // RFC 4959 (SASL-IR): save one round trip
            if ($this->getCapability('SASL-IR')) {
                list($result, $line) = $this->execute("AUTHENTICATE PLAIN", array($reply),
                    Command::COMMAND_LASTLINE | Command::COMMAND_CAPABILITY | Command::COMMAND_ANONYMIZED);
            }
            else {
                $this->putLine($this->nextTag() . " AUTHENTICATE PLAIN");
                $line = trim($this->readReply());

                if (isset($line[0]) && $line[0] != '+') {
                    return $this->parseResult($line);
                }

                // send result, get reply and process it
                $this->putLine($reply, true, true);
                $line   = $this->readReply();
                $result = $this->parseResult($line);
            }
        }

        if ($result === Error::ERROR_OK) {
            // optional CAPABILITY response
            if ($line && preg_match('/\[CAPABILITY ([^]]+)\]/i', $line, $matches)) {
                $this->parseCapability($matches[1], true);
            }
            return $this->fp;
        }else {
            $this->setError($result, "AUTHENTICATE $type: $line");
        }

        return $result;
    }

    private function _connect($host, $port = 143, $options = array())
    {
        if(isset($options['ssl']) && $options['ssl']){
            $host = 'ssl//' . $host;
        } 
        $timeout = GlobalVar::get('imap_timeout', max(0, intval(ini_get('default_socket_timeout'))));
        if(isset($options['timeout']) && $options['timeout']){
            $timeout = (int)$options['timeout']; 
        } 
        GlobalVar::set('imap_timeout', $timeout);
        if(isset($options['socket_options']) && $options['socket_options']){
            $socketOptions = Helper::parseSocketOptions($options['socket_options']);
            $socketContext = stream_context_create($socketOptions); 
            $this->fp      = stream_socket_client(
                $host . ':' . $port
                , $errno
                , $errstr
                , $timeout
                , STREAM_CLIENT_CONNECT
                , $socketContext
            );
        }else{
            $this->fp = @fsockopen($host, $port, $errno, $errstr, $timeout); 
        }

        if(!$this->fp){
            $this->setError(
                Error::ERROR_BAD
                , sprintf('Could not connect to %s:%d: %s', $host, $port, $errstr ?: 'Unknown reason')
            );
            return false;
        }
        if($timeout){
            stream_set_timeout($this->fp, $timeout);
        }    
        $line = trim(fgets($this->fp, 8192));
        if(!preg_match('/^\* (OK|PREAUTH)/i', $line, $match)){
            $error = $line 
                ? sprintf('Wrong startup greeting (%s:%d): %s', $host, $port, $line) : sprintf('Empty start greeting (%s:%d)', $host, $port); 
            $this->setError(Error::ERROR_BAD, $error);
            $this->closeConnection();
            return false;
        }
        $this->data['GREETING'] = trim(preg_replace('/\[[^\]]+\]\s*/', '', $line));
        // RFC3501 [7.1] optional CAPABILITY response
        if (preg_match('/\[CAPABILITY ([^]]+)\]/i', $line, $matches)) {
            $this->parseCapability($matches[1], true);
        }
        return true;
    }

    /**
     * create next command identifier 
     *
     * @access public 
     * @param  void 
     * @return command identifier
     */

    public function nextTag()
    {
        $this->cmdNum++; 
        $this->cmdTag = sprintf('A%04d', $this->cmdNum);
        return $this->cmdTag;
    }

    /**
     * Sends IMAP command and parses result
     *  
     * @access public 
     * @param string $command   IMAP command
     * @param array  $arguments Command arguments
     * @param int    $options   Execution options
     *
     * @return mixed Response code or list of response code and data
     */ 

    public function execute($command, $arguments = array(), $options = 0)
    {
        $tag      = $this->nextTag(); 
        $query    = $tag . ' ' . $command; 
        $noresp   = ($options & Command::COMMAND_NORESPONSE);
        $response = $noresp ? null : ''; 
        if($arguments){
            foreach($arguments as $arg){
                $query .= ' ' . Helper::implodeRecursive($arg); 
            } 
        }

        if(!($res = $this->putLineC($query, $endln = true, ($options & Command::COMMAND_ANONYMIZED)))){
            preg_match('/^[A-Z0-9]+ ((UID )?[A-Z]+)/', $query, $matches); 
            $cmd = isset($matches[1]) ? $matches[1] : 'UNKNOWN'; 
            $this->setError(Error::ERROR_COMMAND, $cmd);
            return $noresp ? Error::ERROR_COMMAND : array(Error::ERROR_COMMAND, '');
        }
        do{
            $line = $this->readLine(4096); 
            if(!is_null($response)){
                $response .= $line; 
            }

        }while(!$this->startsWith($line, $tag . ' ', true, true));

        $code = $this->parseResult($line, $command . ': ');
        if ($response) {
            $line_len = min(strlen($response), strlen($line) + 2);
            $response = substr($response, 0, -$line_len);
        }

        // optional CAPABILITY response
        if (($options & Command::COMMAND_CAPABILITY) && $code == Error::ERROR_OK
            && preg_match('/\[CAPABILITY ([^]]+)\]/i', $line, $matches)
        ) {
            $this->parseCapability($matches[1], true);
        }

        // return last line only (without command tag, result and response code)
        if ($line && ($options & Command::COMMAND_LASTLINE)) {
            $response = preg_replace("/^$tag (OK|NO|BAD|BYE|PREAUTH)?\s*(\[[a-z-]+\])?\s*/i", '', trim($line));
        }
        return $noresp ? $code : array($code, $response);
    }


    public function closeConnection()
    {
        if($this->putLine($this->nextTag() . 'LOGOUT')){
            $this->readReply();
        }
        $this->closeSocket();
    }


    public function setError($errno, $errstr)
    {
        $this->errno  = $errno;
        $this->errstr = $errstr;
    }

    public function getError()
    {
        return array($this->errno, $this->errstr);
    }

    /**
     * close Socket 
     *
     * @access protected 
     * @param  void 
     * @return void 
     */ 

    protected function closeSocket()
    {
        @fclose($this->fp);
        $this->fp = null;
    }

    /**
     * send simple command to connection stream 
     *
     * @access protected 
     * @param  string $string command string 
     * @param  bool   $endln True if CRLF need to be added at the end of command 
     * @return bool 
     */

    protected function putLine($string , $endln = true)
    {
        if(!$this->fp){
            return false;    
        } 
        $string .= $endln ? "\r\n" : '';
        $res = fwrite($this->fp, $string);
        if($res === false){
            $this->closeSocket();
        }
        return $res;
    }

    /**
     * Send command to the connection stream with Command Continuation
     * Requests (RFC3501 7.5) and LITERAL+ (RFC2088) support
     *
     * @access protected 
     *
     * @param string $string     Command string
     * @param bool   $endln      True if CRLF need to be added at the end of command
     * @return int|bool Number of bytes sent, False on error
     */
    protected function putLineC($string, $endln = true)
    {
        if(!$this->fp){
            return false;
        } 
        $string .= $endln ? "\r\n" : '';
        $res = 0;
        if($parts = preg_split('/(\{[0-9]+\}\r\n)/m', $string, -1, PREG_SPLIT_DELIM_CAPTURE)){
            $total = count($parts);
            for($i = 0; $i < $total; $i++){
                if(isset($parts[$i+1]) && preg_match('/^\{([0-9]+)\}\r\n$/', $parts[$i+1], $matches)){
                    if(GlobalVar::get('literal+')){
                        $parts[$i+1] = sprintf("{%d+}\r\n", $matches[1]);    
                    } 

                    $bytes = $this->putLine($parts[$i].$parts[$i+1], false);
                    if ($bytes === false) {
                        return false;
                    }
                    $res += $bytes;
                    if(!GlobalVar::get('literal+')){
                        $line = $this->readLine(1000);
                        if (isset($line[0]) && $line[0] != '+') {
                            return false;
                        } 
                    }
                    $i++;
                }else{
                    $bytes = $this->putLine($parts[$i], false);
                    if ($bytes === false) {
                        return false;
                    }
                    $res += $bytes; 
                }    
            }  
        }
        return $res;
    }

    /**
     * read more data from connection stream 
     * when provided contain string literal 
     *
     * @access protected 
     * @param string $line  Response text 
     * @param bool  enable escape 
     * @return string line of text response 
     */

    protected function multLine($line, $escape = false)
    {
        $line = rtrim($line);    
        if(preg_match('/\{([0-9]+)\}$/', $line, $match)){
            $out = ''; 
            $str = substr($line, 0, -strlen($match[0]));
            $size = $match[1];
            while(strlen($out) < $size){
                $line = $this->readBytes($size); 
                if(is_null($line)){
                    break;
                }
                $out .= $line;
            }
            $line = $str . ($escape ? Helper::escape($out) : $out);
        }
        return $line;
    }

    /**
     * read lines from connection stream 
     *
     * @access protected 
     * @param  int $size buffer size 
     * @return string 
     */ 

    protected function readLine($size = 1024)
    {
        $line = ''; 
        $size = $size ?: 1024;
        do{
            if($this->eof()){
                return $line ?: null;  
            } 
            $buffer = fgets($this->fp, $size);
            if($buffer === false){
                $this->closeSocket();
                break;
            }
            $line .= $buffer;
        }while(substr($buffer, -1) != "\n");

        return $line;
    }

    /**
     * read specified number of bytes from connection stream 
     *
     * @access protected 
     * @param  int $size number of bytes to read 
     * @return string 
     */

    protected function readBytes($size)
    {
        $data = '';    
        $len  = 0;
        while($len < $size && !$this->eof()){
            $tmp = fread($this->fp, $size-$len);
            $data .= $tmp;
            $dataLen = strlen($data);
            if($dataLen == $len){
                break;
            }
            $len = $dataLen;
        }
        return $data;
    }

    /**
     * read complete response to the IMAP command 
     *
     * @access protected 
     * @param  array $untagged all untagged response lines 
     * @return string response 
     */ 

    protected function readReply(&$untagged = null)
    {
        do{
            $line = trim($this->readLine());
            $bool = isset($line[0]) && $line[0] == '*';
            if($bool){
                $untagged[] = $line; 
            }
        }while($bool); 
        if($untagged){
            $untagged = implode("\n", $untagged);
        }
        return $line;
    }

    /**
     * check connection stream state 
     * return true if connection is closed 
     *
     * @access protected 
     * @param  void 
     * @return true/false 
     */

    protected function eof()
    {
        if(!is_resource($this->fp)){
            return true;
        }
        $start = microtime(true);
        if(feof($this->fp)){
            if(GlobalVar::get('imap_timeout') && microtime(true) - $start > GlobalVar::get('imap_timeout')){
                $this->closeSocket();
                return true;
            } 
        }
        return false;
    }

    protected function parseCapability($str)
    {
        $str = preg_replace('/^\* CAPABILITY /i', '', $str);    
        $this->capability = explode(' ', $str);
        if(GlobalVar::get('imap_disabled_caps')){
            $this->capability = array_diff($this->capability, GlobalVar::get('imap_disabled_caps'));
        }
        if(!GlobalVar::has('literal+') && in_array('LITERAL+', $this->capability)){
            GlobalVar::set('literal+', true);
        }
        return;
    }

    /**
     * Response parser.
     *
     * @access public 
     * @param string $string     Response text
     * @param string $prefix Error message prefix
     * @return int Response status
     */

    protected function parseResult($string, $prefix = '')
    {
        if (preg_match('/^[a-z0-9*]+ (OK|NO|BAD|BYE)(.*)$/i', trim($string), $matches)) {
            $res = isset($matches[1]) ? strtoupper($matches[1]) : '';
            $str = isset($matches[2]) ? trim($matches[2]) : '';

            if ($res == 'OK') {
                $this->errno = Error::ERROR_OK;
            }else if ($res == 'NO') {
                $this->errno = Error::ERROR_NO;
            }else if ($res == 'BAD') {
                $this->errno = Error::ERROR_BAD;
            }else if ($res == 'BYE') {
                $this->closeSocket();
                $this->errno = Error::ERROR_BYE;
            }
            if ($str) {
                $str = trim($str);
                // get response string and code (RFC5530)
                if (preg_match("/^\[([a-z-]+)\]/i", $str, $m)) {
                    $this->resultcode = isset($m[1]) ? strtoupper($m[1]) : null;
                    $str = isset($m[1]) ? trim(substr($str, strlen($m[1]) + 2)) : null;
                }else {
                    $this->resultcode = null;
                    // parse response for [APPENDUID 1204196876 3456]
                    if (preg_match("/^\[APPENDUID [0-9]+ ([0-9]+)\]/i", $str, $m)) {
                        $this->data['APPENDUID'] = isset($m[1]) ? $m[1] : null;
                    }
                    // parse response for [COPYUID 1204196876 3456:3457 123:124]
                    else if (preg_match("/^\[COPYUID [0-9]+ ([0-9,:]+) ([0-9,:]+)\]/i", $str, $m)) {
                        $this->data['COPYUID'] = isset($m[1]) && isset($m[2]) ? array($m[1], $m[2]) : array();
                    }
                }
                $this->result = $str;
                if ($this->errno  != Error::ERROR_OK) {
                    $this->errstr = $prefix ? $prefix.$str : $str;
                }
            }
            return $this->errno;
        }
        return Error::ERROR_UNKNOWN;
    }

    /**
     * Checks response status.
     * Checks if command response line starts with specified prefix (or * BYE/BAD)
     *
     * @access protected
     * @param string $string   Response text
     * @param string $match    Prefix to match with (case-sensitive)
     * @param bool   $error    Enables BYE/BAD checking
     * @param bool   $nonempty Enables empty response checking
     * @return bool True any check is true or connection is closed.
     */

    protected function startsWith($string, $match, $error = false, $nonempty = false)
    {
        if (!$this->fp) {
            return true;
        }
        if (strncmp($string, $match, strlen($match)) == 0) {
            return true;
        }
        if ($error && preg_match('/^\* (BYE|BAD) /i', $string, $m)) {
            if (isset($m[1]) && strtoupper($m[1]) == 'BYE') {
                $this->closeSocket();
            }
            return true;
        }
        if ($nonempty && !strlen($string)) {
            return true;
        }
        return false;
    }

    /**
     * Capabilities checker
     */

    protected function hasCapability($name)
    {
        if (empty($this->capability) || $name == '') {
            return false;
        }
        if (in_array($name, $this->capability)) {
            return true;
        }else if (strpos($name, '=')) {
            return false;
        }
        $result = array();
        foreach ($this->capability as $cap) {
            $entry = explode('=', $cap);
            if (isset($entry[0]) && isset($entry[1]) && $entry[0] == $name) {
                $result[] = $entry[1];
            }
        }
        return $result ?: false;
    }

    /**
     * Capabilities checker
     *
     * @access public 
     * @param string $name Capability name
     * @return mixed Capability values array for key=value pairs, true/false for others
     */

    public function getCapability($name)
    {
        $result = $this->hasCapability($name);
        if (!empty($result)) {
            return $result;
        }
        $result = $this->execute('CAPABILITY');
        if (isset($result[0]) && isset($result[1]) && $result[0] == Error::ERROR_OK) {
            $this->parseCapability($result[1]);
        }
        return $this->hasCapability($name);
    }

    public function clearCapability()
    {
        $this->capability = array();
    }

    public function connected()
    {
        return (bool)$this->fp;
    }

    /**
     * NAMESPACE handler (RFC 2342)
     *
     * @access public 
     * @param  void 
     * @return array Namespace data hash (personal, other, shared)
     */

    public function getNamespace()
    {
        if (GlobalVar::has('namespace')) {
            return GlobalVar::get('namespace');
        }
        if (!$this->getCapability('NAMESPACE')) {
            return Error::ERROR_BAD;
        }
        list($code, $response) = $this->execute('NAMESPACE');
        if ($code == Error::ERROR_OK && preg_match('/^\* NAMESPACE /', $response)) {
            $response = substr($response, 11);
            $data     = Helper::tokenizeResponse($response);
        }
        if (!is_array($data)) {
            return $code;
        }
        GlobalVar::set('namespace', array(
            'personal' => $data[0],
            'other'    => $data[1],
            'shared'   => $data[2],
        ));
        return GlobalVar::get('namespace');
    }

    /**
     * Detects hierarchy delimiter
     *
     * @access public 
     * @param  void 
     * @return string The delimiter
     */
    public function getHierarchyDelimiter()
    {
        if (GlobalVar::get('imap_delimiter')) {
            return GlobalVar::get('delimiter');
        }

        // try (LIST "" ""), should return delimiter (RFC2060 Sec 6.3.8)
        list($code, $response) = $this->execute('LIST',
            array(Helper::escape(''), Helper::escape('')));

        if ($code == Error::ERROR_OK) {
            $args = Helper::tokenizeResponse($response, 4);
            $delimiter = $args[3];

            if (strlen($delimiter) > 0) {
                GlobalVar::set('delimiter', $delimiter);
            }
            return $delimiter;
        }
    }

    public function commandID($items = array())
    {
        $args    = [];
        $result  = null;
        foreach((array)$items as $key => $item){
            $args[] = Helper::escape($key, true);
            $args[] = Helper::escape($item, true);
        }    
        $args = $args ? '(' . implode(' ', $args) . ')' :  Helper::escape(null);
        list($code, $response) = $this->execute('ID',  array($args));
        if($code == Error::ERROR_OK && preg_match('/^\* ID /i', $response)){
            $response = substr($response, 5); 
            $items    = Helper::tokenizeResponse($response);
            $length   = count($items); 
            for($i = 0; $i < $length; $i += 2){
                $result[$items[$i]] = isset($items[$i+1]) ? $items[$i+1] : null;    
            }
        }
        return $result;
    }

    /**
     * Send the MYRIGHTS command (RFC4314)
     *
     * @param string $mailbox Mailbox name
     *
     * @return array MYRIGHTS response on success, NULL on error
     */
    public function myRights($mailbox)
    {
        list($code, $response) = $this->execute('MYRIGHTS', array(Helper::escape($mailbox)));

        if ($code == Error::ERROR_OK && preg_match('/^\* MYRIGHTS /i', $response)) {
            // Parse server response (remove "* MYRIGHTS ")
            $response = substr($response, 11);
            $ret_mbox = Helper::tokenizeResponse($response, 1);
            $rights   = Helper::tokenizeResponse($response, 1);
            return str_split($rights);
        }
        return array();
    } 

}
