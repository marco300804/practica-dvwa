<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    if ($_DVWA['SQLI_DB'] == MYSQL) {
        // Check database usando sentencias preparadas (seguro)
        $stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $id);
        $stmt->execute();
        $result = $stmt->get_result();

        // Get results
        while( $row = mysqli_fetch_assoc( $result ) ) {
            // Get values
            $first = $row["first_name"];
            $last  = $row["last_name"];

            // Feedback for end user
            $html .= "<pre>ID: " . htmlspecialchars($id) . "<br />First name: {$first}<br />Surname: {$last}</pre>";
        }

        $stmt->close();
        mysqli_close($GLOBALS["___mysqli_ston"]);

    } elseif ($_DVWA['SQLI_DB'] == SQLITE) {
        global $sqlite_db_connection;

        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
        try {
            $results = $sqlite_db_connection->query($query);
        } catch (Exception $e) {
            echo 'Caught exception: ' . $e->getMessage();
            exit();
        }

        if ($results) {
            while ($row = $results->fetchArray()) {
                // Get values
                $first = $row["first_name"];
                $last  = $row["last_name"];

                // Feedback for end user
                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }
        } else {
            echo "Error in fetch ".$sqlite_db->lastErrorMsg();
        }
    } else {
        // Este es el caso "default" que pedía SonarCloud
        $html .= "<pre>Error: Base de datos no soportada.</pre>";
    }
}


