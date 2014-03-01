<?php
/**
  * Smartcard authentication backend
  *
  * This class itself does not provide any user managment functionality, only searches them from other backends, and forwards user managment operations to them (tested only with plain backend)
  *
  * Quick overview.
  *  
  * Methods:
  * - ____call (calls method on all auth modules marked in $conf['auth']['smartcard']['use_authtypes']
  * - __call (this is magical method called always, if on this class haven't defined this method yet, methodname and args are passed to ____calls but only one value is returned. This is why I did not extend auth_basic.)
  * - checkPass (trys to autenticate with smartcard or if allowed, with password - search is done againts all backends)
  * 
  *
  * @version 2010 05 22
  * @author     mxrgus.pxrt <margus@tione.eu>
  */


// 20100602 this is fix for fckglite, see http://code.google.com/p/dokuwiki-smartcard-authentication/issues/detail?id=1
if(!isset($conf['csrf']) || !$conf['csrf']){
  $conf['csrf'] = md5(rand());
} 
    




define('DOKU_AUTH', dirname(__FILE__));

class auth_smartcard {

  var $success      = true;
  var $cando        = array (
    'addUser'     => true, // can Users be created?
    'delUser'     => true, // can Users be deleted?
    'modLogin'    => true, // can login names be changed?
    'modPass'     => true, // can passwords be changed?
    'modName'     => true, // can real names be changed?
    'modMail'     => true, // can emails be changed?
    'modGroups'   => true, // can groups be changed?
    'getUsers'    => true, // can a (filtered) list of users be retrieved?
    'getUserCount'=> true, // can the number of users be retrieved?
    'getGroups'   => true, // can a list of available groups be retrieved?
    'external'    => false, // does the module do external auth checking?
    'logoff'      => false, // has the module some special logoff method?
    'UserMod'     => true,
    'logout'      => true
  );



  function canDo($what){
    return $this->cando[$what];
  }



  /**
   * Constructor.
   *
   *
   */
  function __construct() {
  }



  /*
  * checkPass
  *
  *
  * This method can cause problems if auth_login function changes a lot (probleby will not change so much), if from auth_login $auth->checkPass 
  * (This method is called, after getting value true back, it makes auth true, it uses input args previosly
  * used on this method and creates session and sets user cookies - problem is that Smartcard user
  * havent given them so we'll write them over here and auth can to is trick.
  *
  * I did not use trustExternal because when writing session and cookie info myself - right click download on file would disconnect session on IE7
  * Also this way seemed more cleaner.
  *
  * @param &$user - as smartcard user useses u=smartcard, we will get value from auth_login replace it and auth_login does it tricks as it should
  * @param &$password - as smartcard user useses p=smartcard, we will get value from auth_login replace it and auth_login does it tricks as it should
  */
  function checkPass(&$username, &$password){
    global $conf;
 
    session_start();
    // ALREADY LOGGED IN - we mess up the password, so we dont really know what it is, and need to get it from session
    if(isset($_SESSION['smartcard_userdata']) && $_SESSION['smartcard_userdata']['username']==$username && md5($_SESSION['smartcard_userdata']['pass'])==$password){
      return true;
    }

    // USERNAME AND PASSWORD LOGIN
    // if password login - auth with username and password
    if($username && $password && $username!='smartcard'){
      // find user by username and password
      $userdata  = $this->findUserByUsernameAndPassword($username, $password);
      // if userdata not found
      if(!$userdata){
        return false;
      }
    }

    // SMARTCARD LOGIN
    // if smartcard login - auth with $_SESSION['SSL_CLIENT_S_DN']
    if($username=='smartcard'){
      // if client cert does not exist
      if(!(isset($_SESSION['SSL_CLIENT_S_DN']) && $_SESSION['SSL_CLIENT_S_DN'])){
        msg('Smartcard was not found. Please check that it is connected and drivers are installed.', -1);
        return false;
      }
      // get serial from dn
      preg_match('/(?<=serialNumber=)\d+/', $_SESSION['SSL_CLIENT_S_DN'], $serial_in_array);
      $serial = $serial_in_array[0];
      // if serial not found
      if(!$serial){
        msg('Did not find valid serial.', -1);
        return false;
      }
      // find user by serial
      $userdata = $this->findUserBySerial($serial);
      // if userdata not found 
      if(!$userdata){ 
        msg('Did not find user with serial: '.$serial, -1); 
        return false;
      }
    }

    // SEE THAT WE GOT SMTH AND LOG HIM IN
    if($userdata){
      // write over gotten args (notice, function was defined: checkPass(&$username, &$password))
      $username           = $userdata['username'];
      $password           = md5($userdata['pass']);
      // set $_SESSION['smartcard_userdata'] because else auth will fail later on because unvalid pw later
      $_SESSION['smartcard_userdata'] = $userdata;
      session_write_close();
      return true;
    }

    // COULD NOT DO LOGIN
    unset($_SESSION['smartcard_userdata']);
    session_write_close();
    return false;
  }



  /**
  * Finds user by username and password
  *
  */
  function findUserByUsernameAndPassword($username, $password){
    // clean
    $username = preg_replace('/[^\w\d\.-_]/', '', $username);
    $password = preg_replace('/[^\w\d\.-_]/', '', $password);

    // it could cause problem that user is defined in two backends (ie plain and mysql) - mysql and plain pw different, auth is succeeds againts mysql, but user data is loaded from plain.
    if($this->__call('checkPass', array($username, $password))){
      // find userdata and return it
      $this->__log(array(__METHOD__, "Found.", $userdata));
      $userdata = $this->__call('getUserData', array($username));
      $userdata['username'] = $username;
      return $userdata;
    }else{
      // if not found
      $this->__log(array(__METHOD__, "Did not find.", $username));
      return false;
    }  
  }



  /**
  * Finds user by serial
  *
  */
  function findUserBySerial($serial){
    // Log and return false if unvalid format
    if(preg_match('/[^\w\d\.]/', $serial) || !$serial){
      $this->__log(array(__METHOD__, "$serial is not valid serial"));
      return false;
    }
    
    // find users -> resolves to __call -> ____call
    $users    = $this->__call('retrieveUsers', array(0, 2000, array('grps'=>$serial))); // receives users only from first place from where it can find them (ideally when serial ok, only 1)

    // if user count 1
    if(count($users)==1){  
      // create username value for user    
      foreach($users as $key => &$value){
        $value['username']  = $key;
      }
      $users  = array_values($users);
      $this->__log(array(__METHOD__, "Found.", $users[0]));
      return $users[0];
    } 
    // if user count more than 1
    if(count($users)>1){
      $this->__log(array(__METHOD__, "$serial for serial found multiple users, that should not happen"));
      return false;
    }
    // no users found
    $this->__log(array(__METHOD__, "$serial not found"));
    return false;    
  }



  /**
  * ____call - delegates all calls to this object to its parents
  *
  * This function needs futher think-through - currently it cant be used so simple, because other classes are also using functionality provided by this - 
  * First none null value is returned - but on all the action is executed, meaning: if you have 4 backends array('plain', 'mysql', 'ad', 'ldap') first values are returned
  * It's more for searching users from multiple backends, not for managing them (but it should manage doing it)
  *
  * @param string $method_name - what was called
  * @param array $method_arguments - what arguments
  * @returns array of results
  */
  function ____call($method_name, $method_arguments){
    global $conf;


    // if $conf['auth']['smartcard']['use_authtypes'] not valid
    if(!isset($conf['auth']['smartcard']['use_authtypes'])){
      // log and return false
      $this->__log(__METHOD__.' \$conf[auth][smartcard][use_authtypes] Must be defined in format: authmodule1,authmodule2,authmodule3.', true, true);
      return false;
    }

    $results  = array();

    // try with different auth modules
    $auth_module_names = preg_split('/,/', $conf['auth']['smartcard']['use_authtypes']);
    foreach($auth_module_names as $auth_module_name){
      // check that name is valid
      if(preg_match('/[^\w\d]/', $auth_module_name) || !$auth_module_name){
        $this->__log(__CLASS__.':'.__METHOD__.' Module name '.$auth_module_name.'is not valid');
        $results[]    = null;
        continue;
      }

      // include class, create object, search for serial and if found return user object
      $include_class_file = DOKU_AUTH.'/'.$auth_module_name.'.class.php';
      $include_class_ok   = include_once($include_class_file);
      $auth_module_class  = 'auth_'.$auth_module_name;

      // check that include went ok
      if(!$include_class_ok){
        // if include went bad log that file was not included, add null value to results and go to new loop
        $this->__log(__CLASS__.':'.__METHOD__.' File not included '.$include_class_file);
        $results[]    = null;
        continue;
      }      
      
      // check that auth class exists
      if(!class_exists($auth_module_class)){
        // if class does not exists log that, add null value to results and go to new loop
        $this->__log(__CLASS__.':'.__METHOD__.' Class not found '.$auth_module_class);
        $results[]    = null;
        continue;
      }

      // check that method exists on the auth module
      if(!method_exists($auth_module_class, $method_name)){
        // add null to results and go to new loop
        $results[]    = null;
        continue;
      }

      $auth_module_ob = new $auth_module_class();      
      $results[]      = call_user_func_array(array($auth_module_ob, $method_name), $method_arguments);
    }    

    $this->__log(array('RESULTS',$method_name,$results));
    return $results;
  }



  /**
  * __call 
  * 
  * for other modules etc first value what evulates to true is returned
  *
  */
  function __call($method_name, $method_arguments=array()){
    $results  = call_user_func_array(array($this, '____call'), array($method_name, $method_arguments));
    foreach($results as $result){
      if($result) return $result;
    }
    // noting did not evulate to true
    return false;
  }



  /**
  * Logs messages to data/log/auth_smartcard.log.txt
  *
  */
  function __log($text, $to_file=true, $to_screen=false){
    global $conf;

    $text = json_encode($text);


    if($to_file && $conf['auth']['smartcard']['log_to_file']){
      @mkdir(DOKU_INC.'/data/pages/log');
      file_put_contents(DOKU_INC.'/data/pages/log/auth_smartcard.log.txt', $text."\n\n", FILE_APPEND);
    }

    if($to_screen){
      msg($text, -1);
    }

  }

}



//Setup VIM: ex: et ts=2 enc=utf-8 :
