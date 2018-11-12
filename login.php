<?php
// Connection with DB
require_once 'appRU/config.php';

// Define variables and initialize with empty values
$phone = $password = "";
$phone_err = $password_err = "";

// Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Check if phone is empty
    if (empty(trim($_POST["phone"]))) {
        $phone_err = 'Please enter phone.';
    } else {
        $phone = trim($_POST["phone"]);
    }

    // Check if password is empty
    if (empty(trim($_POST['password']))) {
        $password_err = 'Please enter your password.';
    } else {
        $password = trim($_POST['password']);
    }

    // Validate credentials
    if (empty($phone_err) && empty($password_err)) {
        // prepare a select statement
        $sql = "SELECT id, phone, password FROM users WHERE phone = ?";

        if ($stmt = $conn->prepare($sql)) {
            // bind variables to the prepared statement as parameters
            $stmt->bind_param("s", $param_phone);
            // set parameters
            $param_phone = $phone;

            // Attempt to execute the prepared statement
            if ($stmt->execute()) {
                // store result
                $stmt->store_result();

                // Check if phone exists, if yes then verify password
                if ($stmt->num_rows == 1) {
                    // bind result variables
                    $stmt->bind_result($user_id, $phone, $hashed_password);

                    if ($stmt->fetch()) {
                        if (password_verify($password, $hashed_password)) {
                            /* password is correct, so start a new session and
                            save the phone to the session */
                            session_start();
                            $_SESSION['phone'] = $phone;
                            $_SESSION['user_id'] = $user_id;
                            header("location: appRU/pages_styled/events.php?user=".$user_id);
                        } else {
                            // display an error message if password is not valid
                            $password_err = 'The password you entered was not valid.';
                        }
                    }
                } else {
                    // display an error message if phone doesn't exist
                    $phone_err = 'No account found with that phone.';
                }
            }
        }
        // close statement
        $stmt->close();
    }
    // close connection
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    
</head>
<body>
<div class="container">
    
</div>
<div class="container">
    <div class="row">
        <div class="col s4"></div>
        <div class="col s4 userForm">
            <h2>Login</h2>
            <p>Please fill in your credentials to login.</p>

            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <div class="form-group <?php echo (!empty($phone_err)) ? 'has-error' : ''; ?>">
                    <label>phone</label>
                    <input type="text" name="phone" class="form-control" value="<?php echo $phone; ?>">
                    <span class="help-block"><?php echo $phone_err; ?></span>
                </div>
                <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                    <label>Password</label>
                    <input type="password" name="password" class="form-control">
                    <span class="help-block"><?php echo $password_err; ?></span>
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-primary" value="Login">
                </div>
                <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
                <p>Forgot password? <a href="forgot.php">Here</a></p>
            </form>
            
        </div>
        <div class="col s4"></div>
    </div>
</div>



</body>
</html>