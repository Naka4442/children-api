<?php 
ini_set('error_reporting', E_ALL); 
ini_set('display_errors', 1); 
ini_set('display_startup_errors', 1);

require_once 'classes/Database.php';
require_once 'vendor/autoload.php';
require_once 'classes/Engine.php';
require_once 'classes/Router.php';

$router = new Router();
// phpinfo();
?>