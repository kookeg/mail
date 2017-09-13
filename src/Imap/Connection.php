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

    protected $resultcode = '';


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


    public function search($mailbox, $query, $returnUid = false, $items = array())
    {
        if(!$this->select($mailbox)){
            return new ResultIndex($mailbox);
        }         

        if (!$this->data['EXISTS']) {
            return new ResultIndex($mailbox, '* SEARCH');
        }

        // If ESEARCH is supported always use ALL
        // but not when items are specified or using simple id2uid search
        if (empty($items) && preg_match('/[^0-9]/', $query)) {
            $items = array('ALL');
        }

        $esearch  = empty($items) ? false : $this->getCapability('ESEARCH');
        $query    = trim($query);
        $params   = '';

        // RFC4731: ESEARCH
        if (!empty($items) && $esearch) {
            $params .= 'RETURN (' . implode(' ', $items) . ')';
        }

        if (!empty($query)) {
            $params .= ($params ? ' ' : '') . $query;
        }
        else {
            $params .= 'ALL';
        }

        list($code, $response) = $this->execute($returnUid ? 'UID SEARCH' : 'SEARCH', array($params));

        $response = $code != Error::ERROR_OK ? null : $response;
        return new ResultIndex($mailbox, $response);
    }

    public function select($mailbox, $qresyncData = array())
    {
        if(!$mailbox){
            return false;
        } 
        $params = array(Helper::escape($mailbox));  
        if(!empty($qresyncData)){
            if(isset($qresyncData[2]) && $qresyncData[2]){
                $qresyncData[2] = Helper::compressMessageSet($qresyncData[2]); 
            }
            $params[] = array('QRESYNC', $qresyncData);
        }
        list($code, $response) = $this->execute('SELECT', $params); 
        if($code == Error::ERROR_OK){
            $response = explode("\r\n", $response);
            foreach ($response as $line) {
                if (preg_match('/^\* OK \[/i', $line)) {
                    $pos   = strcspn($line, ' ]', 6);
                    $token = strtoupper(substr($line, 6, $pos));
                    $pos   += 7;

                    switch ($token) {
                    case 'UIDNEXT':
                    case 'UIDVALIDITY':
                    case 'UNSEEN':
                        if ($len = strspn($line, '0123456789', $pos)) {
                            $this->data[$token] = (int) substr($line, $pos, $len);
                        }
                        break;

                    case 'HIGHESTMODSEQ':
                        if ($len = strspn($line, '0123456789', $pos)) {
                            $this->data[$token] = (string) substr($line, $pos, $len);
                        }
                        break;

                    case 'NOMODSEQ':
                        $this->data[$token] = true;
                        break;

                    case 'PERMANENTFLAGS':
                        $start = strpos($line, '(', $pos);
                        $end   = strrpos($line, ')');
                        if ($start && $end) {
                            $flags = substr($line, $start + 1, $end - $start - 1);
                            $this->data[$token] = explode(' ', $flags);
                        }
                        break;
                    }
                }else if (preg_match('/^\* ([0-9]+) (EXISTS|RECENT|FETCH)/i', $line, $match)) {
                    $token = strtoupper($match[2]);
                    switch ($token) {
                    case 'EXISTS':
                    case 'RECENT':
                        $this->data[$token] = (int) $match[1];
                        break;

                    case 'FETCH':
                        // QRESYNC FETCH response (RFC5162)
                        $line       = substr($line, strlen($match[0]));
                        $fetch_data = Helper::tokenizeResponse($line, 1);
                        $data       = array('id' => $match[1]);

                        for ($i=0, $size=count($fetch_data); $i<$size; $i+=2) {
                            $data[strtolower($fetch_data[$i])] = $fetch_data[$i+1];
                        }

                        $this->data['QRESYNC'][$data['uid']] = $data;
                        break;
                    }
                }else if (preg_match('/^\* VANISHED [()EARLIER]*/i', $line, $match)) {
                    // QRESYNC VANISHED response (RFC5162)
                    $line   = substr($line, strlen($match[0]));
                    $v_data = Helper::tokenizeResponse($line, 1);

                    $this->data['VANISHED'] = $v_data;
                }
            } 
            $this->data['READ-WRITE'] = $this->resultcode != 'READ-ONLY';
            return true;
        }
        return false;
    }


    /**
     * Executes SORT command
     *
     * @param string $mailbox    Mailbox name
     * @param string $field      Field to sort by (ARRIVAL, CC, DATE, FROM, SIZE, SUBJECT, TO)
     * @param string $criteria   Searching criteria
     * @param bool   $returnUid Enables UID SORT usage
     * @param string $encoding   Character set
     *
     * @return ResultIndex Response data
     */
    public function sort(
        $mailbox
        , $field = 'ARRIVAL'
        , $criteria = ''
        , $returnUid = false
        , $encoding = 'US-ASCII'
    )
    {
        $supported = array('ARRIVAL', 'CC', 'DATE', 'FROM', 'SIZE', 'SUBJECT', 'TO');
        $field     = strtoupper($field);
        $field     = $field == 'INTERNALDATE' ? 'ARRIVAL' : $field;


        if (!in_array($field, $supported)) {
            return new ResultIndex($mailbox);
        }

        if (!$this->select($mailbox)) {
            return new ResultIndex($mailbox);
        }

        if (!$this->data['EXISTS']) {
            return new ResultIndex($mailbox, '* SORT');
        }

        // RFC 5957: SORT=DISPLAY
        if (($field == 'FROM' || $field == 'TO') && $this->getCapability('SORT=DISPLAY')) {
            $field = 'DISPLAY' . $field;
        }

        $encoding = $encoding ? trim($encoding) : 'US-ASCII';
        $criteria = $criteria ? 'ALL ' . trim($criteria) : 'ALL';

        list($code, $response) = $this->execute(
            $returnUid ? 'UID SORT' : 'SORT'
            , array("($field)", $encoding, $criteria)
        );

        $response = $code != Error::ERROR_OK ? null : $response;
        return new ResultIndex($mailbox, $response);
    }


    /**
     * Simulates SORT command by using FETCH and sorting.
     *
     * @param string       $mailbox      Mailbox name
     * @param string|array $message_set  Searching criteria (list of messages to return)
     * @param string       $index_field  Field to sort by (ARRIVAL, CC, DATE, FROM, SIZE, SUBJECT, TO)
     * @param bool         $skip_deleted Makes that DELETED messages will be skipped
     * @param bool         $uidfetch     Enables UID FETCH usage
     * @param bool         $returnUid   Enables returning UIDs instead of IDs
     *
     * @return ResultIndex Response data
     */
    public function index(
        $mailbox
        , $message_set
        , $index_field  = ''
        , $skip_deleted = true
        , $uidfetch     = false
        , $returnUid    = false
    )
    {
        $msg_index = $this->fetchHeaderIndex(
            $mailbox
            , $message_set
            , $index_field
            , $skip_deleted
            , $uidfetch
            , $returnUid
        );

        if (!empty($msg_index)) {
            asort($msg_index); // ASC
            $msg_index = array_keys($msg_index);
            $msg_index = '* SEARCH ' . implode(' ', $msg_index);
        }else {
            $msg_index = is_array($msg_index) ? '* SEARCH' : null;
        }

        return new ResultIndex($mailbox, $msg_index);
    }

    /**
     * Fetches specified header/data value for a set of messages.
     *
     * @param string       $mailbox      Mailbox name
     * @param string|array $message_set  Searching criteria (list of messages to return)
     * @param string       $index_field  Field to sort by (ARRIVAL, CC, DATE, FROM, SIZE, SUBJECT, TO)
     * @param bool         $skip_deleted Makes that DELETED messages will be skipped
     * @param bool         $uidfetch     Enables UID FETCH usage
     * @param bool         $returnUid   Enables returning UIDs instead of IDs
     *
     * @return array|bool List of header values or False on failure
     */
    public function fetchHeaderIndex(
        $mailbox
        , $message_set
        , $index_field  = ''
        , $skip_deleted = true
        , $uidfetch     = false
        , $returnUid    = false
    )
    {
        if (is_array($message_set)) {
            if (!($message_set = Helper::compressMessageSet($message_set))) {
                return false;
            }
        }else {
            list($from_idx, $to_idx) = explode(':', $message_set);
            if (empty($message_set) || (isset($to_idx) && $to_idx != '*' && (int)$from_idx > (int)$to_idx)
            ) {
                return false;
            }
        }

        $index_field = empty($index_field) ? 'DATE' : strtoupper($index_field);

        $fields_a['DATE']         = 1;
        $fields_a['INTERNALDATE'] = 4;
        $fields_a['ARRIVAL']      = 4;
        $fields_a['FROM']         = 1;
        $fields_a['REPLY-TO']     = 1;
        $fields_a['SENDER']       = 1;
        $fields_a['TO']           = 1;
        $fields_a['CC']           = 1;
        $fields_a['SUBJECT']      = 1;
        $fields_a['UID']          = 2;
        $fields_a['SIZE']         = 2;
        $fields_a['SEEN']         = 3;
        $fields_a['RECENT']       = 3;
        $fields_a['DELETED']      = 3;

        if (!($mode = $fields_a[$index_field])) {
            return false;
        }

        //  Select the mailbox
        if (!$this->select($mailbox)) {
            return false;
        }

        // build FETCH command string
        $key    = $this->nextTag();
        $cmd    = $uidfetch ? 'UID FETCH' : 'FETCH';
        $fields = array();

        if ($returnUid) {
            $fields[] = 'UID';
        }
        if ($skip_deleted) {
            $fields[] = 'FLAGS';
        }

        if ($mode == 1) {
            if ($index_field == 'DATE') {
                $fields[] = 'INTERNALDATE';
            }
            $fields[] = "BODY.PEEK[HEADER.FIELDS ($index_field)]";
        }
        else if ($mode == 2) {
            if ($index_field == 'SIZE') {
                $fields[] = 'RFC822.SIZE';
            }
            else if (!$returnUid || $index_field != 'UID') {
                $fields[] = $index_field;
            }
        }
        else if ($mode == 3 && !$skip_deleted) {
            $fields[] = 'FLAGS';
        }
        else if ($mode == 4) {
            $fields[] = 'INTERNALDATE';
        }

        $request = "$key $cmd $message_set (" . implode(' ', $fields) . ")";

        if (!$this->putLine($request)) {
            $this->setError(Error::ERROR_COMMAND, "Failed to send $cmd command");
            return false;
        }
        $result = array();
        do {
            $line = rtrim($this->readLine(200));
            $line = $this->multLine($line);

            if (preg_match('/^\* ([0-9]+) FETCH/', $line, $m)) {
                $id     = $m[1];
                $flags  = null;

                if ($returnUid) {
                    if (preg_match('/UID ([0-9]+)/', $line, $matches)) {
                        $id = (int) $matches[1];
                    }
                    else {
                        continue;
                    }
                }
                if ($skip_deleted && preg_match('/FLAGS \(([^)]+)\)/', $line, $matches)) {
                    $flags = explode(' ', strtoupper($matches[1]));
                    if (in_array('\\DELETED', $flags)) {
                        continue;
                    }
                }

                if ($mode == 1 && $index_field == 'DATE') {
                    if (preg_match('/BODY\[HEADER\.FIELDS \("*DATE"*\)\] (.*)/', $line, $matches)) {
                        $value = preg_replace(array('/^"*[a-z]+:/i'), '', $matches[1]);
                        $value = trim($value);
                        $result[$id] = Helper::strtotime($value);
                    }
                    // non-existent/empty Date: header, use INTERNALDATE
                    if (empty($result[$id])) {
                        if (preg_match('/INTERNALDATE "([^"]+)"/', $line, $matches)) {
                            $result[$id] = Helper::strtotime($matches[1]);
                        }
                        else {
                            $result[$id] = 0;
                        }
                    }
                }
                else if ($mode == 1) {
                    if (preg_match('/BODY\[HEADER\.FIELDS \("?(FROM|REPLY-TO|SENDER|TO|SUBJECT)"?\)\] (.*)/', $line, $matches)) {
                        $value = preg_replace(array('/^"*[a-z]+:/i', '/\s+$/sm'), array('', ''), $matches[2]);
                        $result[$id] = trim($value);
                    }
                    else {
                        $result[$id] = '';
                    }
                }
                else if ($mode == 2) {
                    if (preg_match('/' . $index_field . ' ([0-9]+)/', $line, $matches)) {
                        $result[$id] = trim($matches[1]);
                    }
                    else {
                        $result[$id] = 0;
                    }
                }
                else if ($mode == 3) {
                    if (!$flags && preg_match('/FLAGS \(([^)]+)\)/', $line, $matches)) {
                        $flags = explode(' ', $matches[1]);
                    }
                    $result[$id] = in_array("\\".$index_field, (array) $flags) ? 1 : 0;
                }
                else if ($mode == 4) {
                    if (preg_match('/INTERNALDATE "([^"]+)"/', $line, $matches)) {
                        $result[$id] = Helper::strtotime($matches[1]);
                    }
                    else {
                        $result[$id] = 0;
                    }
                }
            }
        }while (!$this->startsWith($line, $key, true, true));

        return $result;
    }

    /**
     * Returns message(s) data (flags, headers, etc.)
     *
     * @param string $mailbox     Mailbox name
     * @param mixed  $message_set Message(s) sequence identifier(s) or UID(s)
     * @param bool   $is_uid      True if $message_set contains UIDs
     * @param bool   $bodystr     Enable to add BODYSTRUCTURE data to the result
     * @param array  $add_headers List of additional headers
     *
     * @return bool|array List of rcube_message_header elements, False on error
     */
    public function fetchHeaders($mailbox, $message_set, $is_uid = false, $bodystr = false, $add_headers = array())
    {
        $query_items = array('UID', 'RFC822.SIZE', 'FLAGS', 'INTERNALDATE');
        $headers     = array('DATE', 'FROM', 'TO', 'SUBJECT', 'CONTENT-TYPE', 'CC', 'REPLY-TO',
            'LIST-POST', 'DISPOSITION-NOTIFICATION-TO', 'X-PRIORITY');

        if (!empty($add_headers)) {
            $add_headers = array_map('strtoupper', $add_headers);
            $headers     = array_unique(array_merge($headers, $add_headers));
        }

        if ($bodystr) {
            $query_items[] = 'BODYSTRUCTURE';
        }

        $query_items[] = 'BODY.PEEK[HEADER.FIELDS (' . implode(' ', $headers) . ')]';

        return $this->fetch($mailbox, $message_set, $is_uid, $query_items);
    }

    /**
     * FETCH command (RFC3501)
     *
     * @param string $mailbox     Mailbox name
     * @param mixed  $message_set Message(s) sequence identifier(s) or UID(s)
     * @param bool   $is_uid      True if $message_set contains UIDs
     * @param array  $query_items FETCH command data items
     * @param string $mod_seq     Modification sequence for CHANGEDSINCE (RFC4551) query
     * @param bool   $vanished    Enables VANISHED parameter (RFC5162) for CHANGEDSINCE query
     *
     * @return array List of rcube_message_header elements, False on error
     * @since 0.6
     */
    public function fetch($mailbox, $message_set, $is_uid = false, $query_items = array(),
        $mod_seq = null, $vanished = false)
    {
        if (!$this->select($mailbox)) {
            return false;
        }

        $message_set = Helper::compressMessageSet($message_set);
        $result      = array();

        $key      = $this->nextTag();
        $cmd      = ($is_uid ? 'UID ' : '') . 'FETCH';
        $request  = "$key $cmd $message_set (" . implode(' ', $query_items) . ")";

        if ($mod_seq !== null && $this->hasCapability('CONDSTORE')) {
            $request .= " (CHANGEDSINCE $mod_seq" . ($vanished ? " VANISHED" : '') .")";
        }

        if (!$this->putLine($request)) {
            $this->setError(self::ERROR_COMMAND, "Failed to send $cmd command");
            return false;
        }

        do {
            $line = $this->readLine(4096);

            if (!$line) {
                break;
            }

            // Sample reply line:
            // * 321 FETCH (UID 2417 RFC822.SIZE 2730 FLAGS (\Seen)
            // INTERNALDATE "16-Nov-2008 21:08:46 +0100" BODYSTRUCTURE (...)
            // BODY[HEADER.FIELDS ...

            if (preg_match('/^\* ([0-9]+) FETCH/', $line, $m)) {
                $id = intval($m[1]);

                $result[$id]            = new MessageHeader;
                $result[$id]->id        = $id;
                $result[$id]->subject   = '';
                $result[$id]->messageID = 'mid:' . $id;

                $headers = null;
                $lines   = array();
                $line    = substr($line, strlen($m[0]) + 2);
                $ln      = 0;

                // get complete entry
                while (preg_match('/\{([0-9]+)\}\r\n$/', $line, $m)) {
                    $bytes = $m[1];
                    $out   = '';

                    while (strlen($out) < $bytes) {
                        $out = $this->readBytes($bytes);
                        if ($out === null) {
                            break;
                        }
                        $line .= $out;
                    }

                    $str = $this->readLine(4096);
                    if ($str === false) {
                        break;
                    }

                    $line .= $str;
                }

                // Tokenize response and assign to object properties
                while (list($name, $value) = Helper::tokenizeResponse($line, 2)) {
                    if ($name == 'UID') {
                        $result[$id]->uid = intval($value);
                    }
                    else if ($name == 'RFC822.SIZE') {
                        $result[$id]->size = intval($value);
                    }
                    else if ($name == 'RFC822.TEXT') {
                        $result[$id]->body = $value;
                    }
                    else if ($name == 'INTERNALDATE') {
                        $result[$id]->internaldate = $value;
                        $result[$id]->date         = $value;
                        $result[$id]->timestamp    = Helper::strtotime($value);
                    }
                    else if ($name == 'FLAGS') {
                        if (!empty($value)) {
                            foreach ((array)$value as $flag) {
                                $flag = str_replace(array('$', "\\"), '', $flag);
                                $flag = strtoupper($flag);

                                $result[$id]->flags[$flag] = true;
                            }
                        }
                    }
                    else if ($name == 'MODSEQ') {
                        $result[$id]->modseq = $value[0];
                    }
                    else if ($name == 'ENVELOPE') {
                        $result[$id]->envelope = $value;
                    }
                    else if ($name == 'BODYSTRUCTURE' || ($name == 'BODY' && count($value) > 2)) {
                        if (!is_array($value[0]) && (strtolower($value[0]) == 'message' && strtolower($value[1]) == 'rfc822')) {
                            $value = array($value);
                        }
                        $result[$id]->bodystructure = $value;
                    }
                    else if ($name == 'RFC822') {
                        $result[$id]->body = $value;
                    }
                    else if (stripos($name, 'BODY[') === 0) {
                        $name = str_replace(']', '', substr($name, 5));

                        if ($name == 'HEADER.FIELDS') {
                            // skip ']' after headers list
                            Helper::tokenizeResponse($line, 1);
                            $headers = Helper::tokenizeResponse($line, 1);
                        }
                        else if (strlen($name)) {
                            $result[$id]->bodypart[$name] = $value;
                        }
                        else {
                            $result[$id]->body = $value;
                        }
                    }
                }

                // create array with header field:data
                if (!empty($headers)) {
                    $headers = explode("\n", trim($headers));
                    foreach ($headers as $resln) {
                        if (ord($resln[0]) <= 32) {
                            $lines[$ln] .= (empty($lines[$ln]) ? '' : "\n") . trim($resln);
                        }
                        else {
                            $lines[++$ln] = trim($resln);
                        }
                    }

                    foreach ($lines as $str) {
                        list($field, $string) = explode(':', $str, 2);

                        $field  = strtolower($field);
                        $string = preg_replace('/\n[\t\s]*/', ' ', trim($string));

                        switch ($field) {
                            case 'date';
                            $result[$id]->date = $string;
                            $result[$id]->timestamp = Helper::strtotime($string);
                            break;
                        case 'to':
                            $result[$id]->to = preg_replace('/undisclosed-recipients:[;,]*/', '', $string);
                            break;
                        case 'from':
                        case 'subject':
                        case 'cc':
                        case 'bcc':
                        case 'references':
                            $result[$id]->{$field} = $string;
                            break;
                        case 'reply-to':
                            $result[$id]->replyto = $string;
                            break;
                        case 'content-transfer-encoding':
                            $result[$id]->encoding = $string;
                            break;
                        case 'content-type':
                            $ctype_parts = preg_split('/[; ]+/', $string);
                            $result[$id]->ctype = strtolower(array_shift($ctype_parts));
                            if (preg_match('/charset\s*=\s*"?([a-z0-9\-\.\_]+)"?/i', $string, $regs)) {
                                $result[$id]->charset = $regs[1];
                            }
                            break;
                        case 'in-reply-to':
                            $result[$id]->in_reply_to = str_replace(array("\n", '<', '>'), '', $string);
                            break;
                        case 'return-receipt-to':
                        case 'disposition-notification-to':
                        case 'x-confirm-reading-to':
                            $result[$id]->mdn_to = $string;
                            break;
                        case 'message-id':
                            $result[$id]->messageID = $string;
                            break;
                        case 'x-priority':
                            if (preg_match('/^(\d+)/', $string, $matches)) {
                                $result[$id]->priority = intval($matches[1]);
                            }
                            break;
                        default:
                            if (strlen($field) < 3) {
                                break;
                            }
                            if (isset($result[$id]->others[$field])) {
                                $string = array_merge((array)$result[$id]->others[$field], (array)$string);
                            }
                            $result[$id]->others[$field] = $string;
                        }
                    }
                }
            }
            // VANISHED response (QRESYNC RFC5162)
            // Sample: * VANISHED (EARLIER) 300:310,405,411
            else if (preg_match('/^\* VANISHED [()EARLIER]*/i', $line, $match)) {
                $line   = substr($line, strlen($match[0]));
                $v_data = Helper::tokenizeResponse($line, 1);

                $this->data['VANISHED'] = $v_data;
            }
        }
        while (!$this->startsWith($line, $key, true));

        return $result;
    }

    /**
     * Executes THREAD command
     *
     * @param string $mailbox    Mailbox name
     * @param string $algorithm  Threading algorithm (ORDEREDSUBJECT, REFERENCES, REFS)
     * @param string $criteria   Searching criteria
     * @param bool   $return_uid Enables UIDs in result instead of sequence numbers
     * @param string $encoding   Character set
     *
     * @return ResultThread Thread data
     */
    public function thread(
        $mailbox
        , $algorithm = 'REFERENCES'
        , $criteria = ''
        , $return_uid = false
        , $encoding = 'US-ASCII'
    )
    {

        if (!$this->select($mailbox)) {
            return new ResulThread($mailbox);
        }

        if (!$this->data['EXISTS']) {
            return new ResulThread($mailbox, '* THREAD');
        }

        $encoding  = $encoding ? trim($encoding) : 'US-ASCII';
        $algorithm = $algorithm ? trim($algorithm) : 'REFERENCES';
        $criteria  = $criteria ? 'ALL '.trim($criteria) : 'ALL';

        list($code, $response) = $this->execute($return_uid ? 'UID THREAD' : 'THREAD',
            array($algorithm, $encoding, $criteria));

        $response = $code != Error::ERROR_OK ? null : $response;
        return ResulThread($mailbox, $response);
    }


    /**
     * Returns count of all messages in a folder
     *
     * @param string $mailbox Mailbox name
     *
     * @return int Number of messages, False on error
     */
    public function countMessages($mailbox)
    {
        $counts = $this->status($mailbox);
        if (is_array($counts)) {
            return (int) $counts['MESSAGES'];
        }
        return 0;
    }

    /**
     * Returns count of messages with \Recent flag in a folder
     *
     * @param string $mailbox Mailbox name
     *
     * @return int Number of messages, False on error
     */
    public function countRecent($mailbox)
    {
        $cache = $this->data['STATUS:'.$mailbox];
        if (!empty($cache) && isset($cache['RECENT'])) {
            return (int) $cache['RECENT'];
        }

        $counts = $this->status($mailbox, array('RECENT'));
        if (is_array($counts)) {
            return (int) $counts['RECENT'];
        }

        return false;
    }

    /**
     * Returns count of messages without \Seen flag in a specified folder
     *
     * @param string $mailbox Mailbox name
     *
     * @return int Number of messages, False on error
     */
    public function countUnseen($mailbox)
    {
        // Check internal cache
        $cache = $this->data['STATUS:'.$mailbox];
        if (!empty($cache) && isset($cache['UNSEEN'])) {
            return (int) $cache['UNSEEN'];
        }

        // Try STATUS (should be faster than SELECT+SEARCH)
        $counts = $this->status($mailbox);
        if (is_array($counts)) {
            return (int) $counts['UNSEEN'];
        }

        // Invoke SEARCH as a fallback
        $index = $this->search($mailbox, 'ALL UNSEEN', false, array('COUNT'));
        if (!$index->is_error()) {
            return $index->count();
        }

        return false;
    }


    /**
     * Executes STATUS command
     *
     * @param string $mailbox Mailbox name
     * @param array  $items   Additional requested item names. By default
     *                        MESSAGES and UNSEEN are requested. Other defined
     *                        in RFC3501: UIDNEXT, UIDVALIDITY, RECENT
     *
     * @return array Status item-value hash
     * @since 0.5-beta
     */
    public function status($mailbox, $items = array())
    {
        if (!strlen($mailbox)) {
            return false;
        }

        if (!in_array('MESSAGES', $items)) {
            $items[] = 'MESSAGES';
        }
        if (!in_array('UNSEEN', $items)) {
            $items[] = 'UNSEEN';
        }

        list($code, $response) = $this->execute('STATUS', array(Helper::escape($mailbox),
            '(' . implode(' ', $items) . ')'));

        if ($code == Error::ERROR_OK && preg_match('/^\* STATUS /i', $response)) {
            $result   = array();
            $response = substr($response, 9); // remove prefix "* STATUS "

            list($mbox, $items) = Helper::tokenizeResponse($response, 2);

            // Fix for #1487859. Some buggy server returns not quoted
            // folder name with spaces. Let's try to handle this situation
            if (!is_array($items) && ($pos = strpos($response, '(')) !== false) {
                $response = substr($response, $pos);
                $items    = Helper::tokenizeResponse($response, 1);
            }

            if (!is_array($items)) {
                return $result;
            }

            for ($i=0, $len=count($items); $i<$len; $i += 2) {
                $result[$items[$i]] = $items[$i+1];
            }

            $this->data['STATUS:'.$mailbox] = $result;
            return $result;
        }
        return false;
    }

    /**
     * Executes EXPUNGE command
     *
     * @param string       $mailbox  Mailbox name
     * @param string|array $messages Message UIDs to expunge
     *
     * @return boolean True on success, False on error
     */
    public function expunge($mailbox, $messages = null)
    {
        if (!$this->select($mailbox)) {
            return false;
        }

        if (!$this->data['READ-WRITE']) {
            $this->setError(self::ERROR_READONLY, "Mailbox is read-only");
            return false;
        }

        if (!empty($messages) && $messages != '*' && $this->hasCapability('UIDPLUS')) {
            $messages = Helper::compressMessageSet($messages);
            $result   = $this->execute('UID EXPUNGE', array($messages), Command::COMMAND_NORESPONSE);
        }
        else {
            $result = $this->execute('EXPUNGE', null, Command::COMMAND_NORESPONSE);
        }

        if ($result == Error::ERROR_OK) {
            return true;
        }
        return false;
    }

}
