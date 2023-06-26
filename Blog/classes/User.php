<?php
class User {
    //لازما نستدعى كلاس الربط ولازما يكون private
    private $pdo;
    
    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function register($username, $email, $password) {
        $errors = array();

        if (empty($username)) {
            $errors[] = "Please enter a username";
        }
        if (empty($email)) {
            $errors[] = "Please enter a email";
        }
        if (empty($password)) {
            $errors[] = "Please enter a password";
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Please enter a valid email address.";
        }

        $stmt = $this->pdo->prepare("SELECT count(*) FROM users WHERE username = :username OR email = :email");
        $stmt->execute(array(':email' => $email, ':username' => $username));
        $count = $stmt->fetchColumn();
        if ($count > 0) {
            $errors[] = "Username or Email address already in use.";
        }

        if (empty($errors)) {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
            $stmt->execute(array(':username' => $username, ':email' => $email, ':password' => $hash));
            
            return true;
        } else {
            return $errors;
        }
    }

    public function login($email , $password)
    {
        $errors = array();

    
        if (empty($email)) {
            $errors[] = "Please enter a email";
        }
        if (empty($password)) {
            $errors[] = "Please enter a password";
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Please enter a valid email address.";
        }

        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->execute(array(':email' => $email));
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
       
        
     if($user && password_verify($password , $user['password'])){

        $_SESSION['user_id']=$user['id'];
            $_SESSION['username']=$user['username'];
            $_SESSION['email']=$user['email'];
            header('Location: home.php');
        return true;
        exit;

     }else{
        return "The Email OR Password incorrect";
     }



    }
}



?>


