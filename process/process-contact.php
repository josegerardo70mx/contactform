<?php

    /**
     * This example shows sending a message using PHP's mail() function.
     */

    //Import the PHPMailer class into the global namespace
    use PHPMailer\PHPMailer\PHPMailer;

    // Only process POST reqeusts.
    if ($_SERVER["REQUEST_METHOD"] == "POST") {

        // Check Injection
        function sanitize($data) {
            $data   = trim($data);
            $data   = stripslashes($data);
            $data   = htmlspecialchars($data);
            return $data;
        }

        // Get The form data
        $name       = sanitize($_POST['name']);
        $email      = sanitize($_POST['email']);
        $message    = sanitize($_POST['message']);

        // Check that data was sent to the mailer.
        $errors = array();

        if(isset($_POST['name'], $_POST['email'], $_POST['message'])) {
            $fields = array(
                'name'      => $_POST['name'],
                'email'     => $_POST['email'],
                'message'   => $_POST['message']
            );

            foreach ($fields as $field => $data) {
                if(empty($data)) {
                    // $errors[] = "The " . $field . " is required";
                    $errors[] = "Please fill-up the form correctly.";
                    break 1;
                }
            }

            if(empty($errors) === true) {
                if(!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
                    $errors[] = "Oops! Invalid E-mail!";
                }
            }

        }

        // If Get Errors 
        if(empty($errors) === false) {
            // Set a 400 (bad request) response code and exit.
            http_response_code(400);
            echo implode(" ",$errors);
            exit;
        }

        // If didn't Get Errors then sending mail
        if(empty($errors) === true) {

            // Get the referral URL
            $my_php_self            = $_SERVER['PHP_SELF'];
            $my_server_name         = $_SERVER['SERVER_NAME'];
            $my_host_name           = $_SERVER['HTTP_HOST'];
            $question_mark          = "?";
            $my_string              = $_SERVER['QUERY_STRING'];
            $referrer               = $my_server_name .$my_php_self . $question_mark . $my_string;

            // Get the user location
            if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
                $user_ip = $_SERVER['HTTP_CLIENT_IP'];
            } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $user_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
            } else {
                $user_ip = $_SERVER['REMOTE_ADDR'];
            }
            $geo            = unserialize(file_get_contents('http://www.geoplugin.net/php.gp?ip='.$user_ip));
            $city           = $geo["geoplugin_city"];
            $region         = $geo["geoplugin_regionName"];
            $country        = $geo["geoplugin_countryName"];
            $geo_location   = $city . ", " . $region . ", " . $country;

            // Build the email content.
            $vars = array(
                '%name%'            => $name,
                '%email%'           => $email,
                '%message%'         => $message,
                '%user_ip%'         => $user_ip,
                '%geo_location%'    => $geo_location,
                '%referrer%'        => $referrer
            );

            require 'vendor/autoload.php';
            //Create a new PHPMailer instance
            $mail = new PHPMailer;
            $mail->CharSet = "UTF-8";
            //Set who the message is to be sent from
            $mail->setFrom('contacto@tupaginawebmx.com', 'tupaginawebmx.com');
            //Set an alternative reply-to address
            $mail->addReplyTo($email, $name);
            //Set who the message is to be sent to
            $mail->addAddress('josegarguelless70@gmail.com');
            //Set the subject line
            $mail->Subject = 'You have a new message from ' . $name;
            //Read an HTML message body from an external file, convert referenced images to embedded,
            //convert HTML into a basic plain-text alternative body
            $mail->msgHTML(strtr(file_get_contents('process-contact-email.html'), $vars));
            //Replace the plain text body with one created manually
            // $mail->AltBody = 'This is a plain-text message body';
            //Attach an image file
            // $mail->addAttachment('images/phpmailer_mini.png');

            //send the message, check for errors
            if (!$mail->send()) {
                // echo "Mailer Error: " . $mail->ErrorInfo;

                // Set a 500 (internal server error) response code.
                http_response_code(500);
                echo "Oops! Something went wrong and we couldn't send your message.";
            } else {
                // Set a 200 (okay) response code.
                http_response_code(200);
                echo "Gracias! tu mensaje a sido enviado...";
            }
            // PHPMailer END 
        }
    } else {
        // Not a POST request, set a 403 (forbidden) response code.
        http_response_code(403);
        // echo "There was a problem with your submission, please try again.";
        header('Location: ../');
    }
?>