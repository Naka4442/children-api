<?php
use \Firebase\JWT\JWT;
    class User {

        private $data;

        function __construct($data) {
            $this->data = $data;
        }

        //Аунтефикация
        public function auth(){
            global $db;
            if($this->data["method"] === "POST"){
                $login = md5($this->data["login"]);
                $password = $this->data["password"];
                mb_internal_encoding("UTF-8");
    
                $sql = "SELECT * FROM `Users` WHERE `Login` = :login";
                        
                $data = array("login" => $login);
    
                $user_info = $db->doRequest($sql, $data);
                // print_r($user_info);
                if(!$user_info) return array('json' => 'nopee', 'status' => 401);
    
                $decrypted_password = Engine::decrypt($user_info[0]["Password"], Engine::$ck, $user_info[0]["Token"]);
                
                
                if($decrypted_password == $password) {
                    $decrypted_name = Engine::decrypt($user_info[0]["Name"], Engine::$ck, $user_info[0]["Token"]);
                    $decrypted_second_name = Engine::decrypt($user_info[0]["SecondName"], Engine::$ck, $user_info[0]["Token"]);
                    $token = $this->createToken($user_info[0]["Id"], $user_info[0]["StatusId"]);
                    $sql = "UPDATE `Users` SET `RefreshToken` = :rt WHERE `Id` = :id";
                    $data = array("rt" => $token["Refresh_token"], "id" => $user_info[0]["Id"]);
                    $db->doRequest($sql, $data);

                    $token["user"] = array(
                        "id" => $user_info[0]["Id"],
                        "login" => $this->data["login"],
                        "name" => $decrypted_name,
                        "secondname" => $decrypted_second_name,
                        "status" => $user_info[0]["StatusId"]
                    );

                    return array('json' => json_encode($token), 'status' => 200);
                }
                else return array('json' => 'Unauthorized', 'status' => 401);
            }
            else{
                return array('json' => 'Wrong request type', 'status' => 405);
            }
        }

        public function refreshToken() {
            global $db;
            if($this->data["method"] === "POST"){
                if(isset($this->data["refreshToken"])) {
                    $sql = "SELECT * FROM `Users` WHERE `RefreshToken` = :rt";
                    $data = array("rt" => $this->data["refreshToken"]);
                    $user = $db->doRequest($sql, $data);
                    if($user) {
                        $token = $this->createToken($user[0]["Id"], $user[0]["Status"]);

                        $sql = "UPDATE `Users` SET `RefreshToken` = :rt WHERE `Id` = :id";
                        $data = array("rt" => $token["Refresh_token"], "id" => $user[0]["Id"]);
                        $db->doRequest($sql, $data);

                        return array('json' => json_encode($token), 'status' => 200);
                    }
                    else {
                        $this->logout();
                        return array('json' => 'Unauthorized', 'status' => 401);
                    } 
                }
                else return array('json' => 'Bad request', 'status' => 405);
            }
            else return array('json' => 'Wrong request type', 'status' => 405);
        }

        private function createToken($uId, $status) {
            $token = array(
                "userId" => $uId,
                "exp" => time() + 3600 * 24,
                "createTime" => time(),
                "status" => $status,
                "type" => "access"
            );
            $jwt = JWT::encode($token, Engine::$ck);

            $refresh_token = array(
                "userId" => $uId,
                "type" => "refresh",
                "exp" => time() + 3600*24
            );

            $rt = JWT::encode($refresh_token, Engine::$ck);

            $ans = array(
                "Access_token" => $jwt,
                "Refresh_token" => $rt
            );

            return $ans;
        }   

        public function addNewUser() {
            global $db;
            if($this->data["method"] != "POST") return array('json' => 'Wrong request type', 'status' => 405);
            if(!Engine::checkAuth($this->data["auth"])) return array('json' => "Unauthorized", 'status' => 401);
            if(!Engine::isAdmin($this->data["auth"])) return array('json' => "Wrong user type", 'status' => 405);
            if(!isset($this->data["login"]) || !isset($this->data["password"]) || !isset($this->data["status"])) return array('json' => "Bad request", 'status' => 400);

            $email = $this->data["login"];
            $password = $this->data["password"];
            $status = $this->data["status"];

            $sql = "INSERT INTO `Users`(`Email`, `Login`, `Password`, `Hash`, `Status`) VALUES (:email, :login, :password, :salt, :status)";

            $email = md5($email);
            $salt = Engine::generate_code(8);
            $password = Engine::encrypt($password, Engine::$ck, $salt);

            $data = array(
                "email" => $email,
                "login" => $email,
                "password" => $password,
                "salt" => $salt,
                "status" => $status
            );
            $db->doRequest($sql, $data);

            return array('json' => true, 'status' => 201);
        }

        public function reg() {
            global $db;
            if($this->data["method"] === "POST"){
                $email = $this->data["login"];
                $login = $email;
                $password = $this->data["password"];
                $status_id = 3;
                $name = $this->data["name"];
                $secondname = $this->data["secondname"];
                $groupid = $this->data["groupid"];
    
                $sql = "INSERT INTO `Users` (`Email`, `Login`, `Name`, `SecondName` ,`Password`, `StatusId`, `Token`, `GroupId`) VALUES (:email, :login, :name, :secondname, :password, :statusid, :token, :fromwho)";
    
                $login = md5($login);
                $token = Engine::generate_code(8);
                $email = Engine::encrypt($email, Engine::$ck, $token);
                $password = Engine::encrypt($password, Engine::$ck, $token);
                $name = Engine::encrypt($name, Engine::$ck, $token);
                $secondname = Engine::encrypt($secondname, Engine::$ck, $token);
    
                $data = array(
                    "email" => $email,
                    "login" => $login,
                    "name" => $name,
                    "secondname" => $secondname,
                    "password" => $password,
                    "statusid" => $status_id,
                    "token" => $token,
                    "groupid" => $groupid
                );
                $db->doRequest($sql, $data);
    
                // print_r($data);
    
                return array('json' => true, 'status' => 201);
            }
            else{
                return array('json' => 'Wrong request type', 'status' => 405);
            }
        }

        public function logout() {
            global $db;
            $sql = "UPDATE `Users` SET `RefreshToken` = :rt WHERE `Id` = :id";
            $data = array("rt" => "", "id" => $this->data["userId"]);
            $db->doRequest($sql, $data);
        }

        public function addCode(){
            global $db;
            if($this->data["method"] === "POST"){
                //Проверка авторизации
                if(Engine::checkAuth($this->data["auth"])){
                    if(isset($this->data["code"]) && strlen($this->data["code"]) <= 8){
                        $userId = Engine::getUserId($this->data["auth"]);
                        // Проверка на пользователя
                        $sql = "SELECT * FROM `ReferalCodes` WHERE `UserId` = :userid";
                        $data = array(
                            "userid" => $userId
                        );
                        $code = $db->doRequest($sql, $data);
                        if(empty($code)){
                            // Проверка на совпадение кода
                            $sql = "SELECT * FROM `ReferalCodes` WHERE `Code` = :code";
                            $code = $this->data["code"];
                            $data = array(
                                "code" => $code
                            );
                            $code = $db->doRequest($sql, $data);
                            if(empty($code)){
                                //Добавление
                                $sql = "INSERT INTO `ReferalCodes` (`UserId`, `Code`) VALUES (:userid, :code)";
                                $code = $this->data["code"];
                                $data = array(
                                    "userid" => $userId,
                                    "code" => $code
                                );
                                $db->doRequest($sql, $data);
                                return array('json' => true, 'status' => 200);
                            }
                        }
                        else{
                            $sql = "SELECT * FROM `ReferalCodes` WHERE `Code` = :code";
                            $code = $this->data["code"];
                            $data = array(
                                "code" => $code
                            );
                            $code = $db->doRequest($sql, $data);
                            if(empty($code)){
                                //Обновление
                                $sql = "UPDATE `ReferalCodes` SET `Code` = :code WHERE `UserId` = :userid";
                                $code = $this->data["code"];
                                $data = array(
                                    "userid" => $userId,
                                    "code" => $code
                                );
                                $db->doRequest($sql, $data);
                                return array('json' => true, 'status' => 200);
                            }
                            else{
                                return array('json' => json_encode(array("message" => "Такой код уже есть")), 'status' => 400);
                            }
                        }
                    }
                    else{
                        return array('json' => json_encode(array("message" => "Кода нет или он больше 8 символов")), 'status' => 400);
                    }
                }
                else{
                    return array('json' => "Unauthorized", 'status' => 401);
                }
            }
            else{
                return array('json' => 'Wrong request type', 'status' => 405);
            }
        }

        public function getCode(){
            global $db;
            if($this->data["method"] === "POST"){
                if(Engine::checkAuth($this->data["auth"])){
                    $userId = Engine::getUserId($this->data["auth"]);
                    $sql = "SELECT * FROM `ReferalCodes` WHERE `UserId` = :userid";
                    $data = array(
                        "userid" => $userId
                    );
                    $code = $db->doRequest($sql, $data);
                    if(!empty($code)){
                        return array('json' => json_encode($code[0]["Code"]), 'status' => 200);
                    }
                    else{
                        return array('json' => false, 'status' => 404);
                    }
                }
                else{
                    return array('json' => "Unauthorized", 'status' => 401);
                }
            }
            else{
                return array('json' => 'Wrong request type', 'status' => 405);
            }
        }

        public function checkCode(){
            global $db;
            if($this->data["method"] === "GET"){
                $code = $this->data["code"];
                $sql = "SELECT `UserId` FROM `ReferalCodes` WHERE `Code` = :code";
                $data = array("code" => $code);
                $result = $db->doRequest($sql, $data);
                if(!empty($result)){
                    return array('json' => json_encode($result[0]["UserId"]), 'status' => 200);
                }
                else{
                    return array('json' => json_encode(false), 'status' => 400);
                }
            }
            else{
                return array('json' => 'Wrong request type', 'status' => 405);
            }
        }

    }

?>