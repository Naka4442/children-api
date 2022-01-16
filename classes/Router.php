<?php

class Router{

    private $requestMethod;
    public $args;
    public $headers;

    private $fileTypes = array(
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );

    public function __construct(){
        
        $this->requestMethod = $_SERVER["REQUEST_METHOD"];
        $this->headers = $this->getRequestHeaders();
        if($this->requestMethod == "OPTIONS") {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, authorization, Content-Disposition, Content-Transfer-Encoding');
            header('Access-Control-Allow-Credentials: true');
        }
        else if(true){
            $this->args = $this->findArgs();
            if(isset($_GET["class"])&&isset($_GET["action"])){

                $name = $_GET["class"];
                $method = $_GET["action"];
                // Подключение нужного класса
                if(file_exists("classes/api/".$name.".php")){
                    require_once("classes/api/".$name.".php");
                    $obj = new $name($this->args);
                    // Вызов нужного метода, если он существует 
                    if(method_exists($obj, $method)){
                        $ans = $obj->$method();
                        if($ans['status'] == 200) echo $this->response($ans['json']);
                        else echo $this->response($ans['json'], $ans['status']);
                    }
                    else{
                        echo $this->response("", 405);
                    }
                }
                else{
                    echo $this->response("", 405);
                }

            }
        }
        else{
            if($this->requestMethod !== "GET"){
                echo $this->response("There's no JSON", 415);
            }
        }

    }

    private function getRequestHeaders() {
        $headers = array();
        foreach($_SERVER as $key => $value) {
            if (substr($key, 0, 5) <> 'HTTP_') {
                continue;
            }
            $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
            $headers[$header] = $value;
        }
        return $headers;
    }
    
    private function findArgs(){
        switch($this->requestMethod){
            case "GET":
                $_GET["method"] = "GET";
                if(isset(getallheaders()["authorization"]))$_GET["auth"] = getallheaders()["authorization"];
                $data["files"] = $this->findFiles();
                return $_GET;
                break;
            case "POST":
                $data = json_decode(file_get_contents("php://input"), true);
                if(isset(getallheaders()["authorization"]))$data["auth"] = getallheaders()["authorization"];
                $data["files"] = $this->findFiles();
                $data["method"] = "POST";
                $data["get"] = $_GET;
                return $data;
                break;
            case "PUT":
                $data = json_decode(file_get_contents("php://input"), true);
                if(isset(getallheaders()["authorization"]))$data["auth"] = getallheaders()["authorization"];
                $data["files"] = $this->findFiles();
                $data["method"] = "PUT";
                $data["get"] = $_GET;
                return $data;
                break;
            case "DELETE":
                $data = json_decode(file_get_contents("php://input"), true);
                if(isset(getallheaders()["authorization"]))$data["auth"] = getallheaders()["authorization"];
                $data["files"] = $this->findFiles();
                $data["method"] = "DELETE";
                $data["get"] = $_GET;
                return $data;
                break;
            default:
                return false;
                break;
        }
    }

    private function findFiles(){
        $files = array();
        foreach($_FILES as $key => $file){
            if(in_array($file["type"],$this->fileTypes)){
                $files[] = array(
                    "name" => $key,
                    "filename" => $file["name"],
                    "type" => $file["type"],
                    "tmp"  => $file["tmp_name"],
                    "size" => $file["size"]
                );
            }
        }
        if(!empty($files)) {
            return $files;
        }
        else{
            return false;
        }
    }

    private function response($data, $status = 200){

        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, authorization, Content-Disposition, Content-Transfer-Encoding');
        header('Access-Control-Allow-Credentials: true');
        header("HTTP/1.1 " . $status . " " . $this->requestStatus($status));
        return $data; 

    }

    private function requestStatus($code){

        $status = array(
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        415 => 'Unsupported Media Type',
        500 => 'Internal Server Error',
        );
        return ($status[$code])?$status[$code]:$status[500];
    
    }

}

?>