<?php


$conf['authtype']   = 'smartcard';


// this creates empty array for smartcard conf plugin
$conf['smartcard']                            = array();
// if this is set to true, without smartcard login is not allowed
$conf['smartcard']['allow_without_smartcard'] = true;
// if user tries to log in with smartcard, all those auth modules are used
$conf['smartcard']['use_authtypes']           = array('plain');
// if we want to log all authentication try info to http://www.mywikidomain.ee/log/auth_smartcard.log then we set this value to true (hide this page using ACL from your users and enable to admins only)
$conf['smartcard']['log_file']                = true;




// 20100602 this is fix for fckglite, see http://code.google.com/p/dokuwiki-smartcard-authentication/issues/detail?id=1
if(!isset($conf['csrf']) || !$conf['csrf']){
    $conf['csrf'] = md5(rand());
} 
  // /this is fix for fckglite
  