<?php
	include("db_conn.php");
	// DB schema:
	//     users(username, password)
	//     messages(id, username, ip_addr, message, timestmp)
	try {
		$db = new PDO("mysql:host=$db_server;dbname=$db_name", $db_username, $db_password);
	} catch (PDOException $e) {
		$db = NULL;
		error_log('Error connecting to DB: ' . $e->getMessage());
	}

	// These 2 lines of code would make this site resistant against XSRF:
	// $samesite = 'lax';
	// session_set_cookie_params($samesite);

	session_start();

	$login_failed = false;
	if (isset($_POST["login_submit"]) && !is_null($db)) {
		// Check credentials for correctness and then set $_SESSION["login"] and $_SESSION["username"]:
		$login_failed = true;
		$statement = $db->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
		$statement->execute(array($_POST["uname"], $_POST["pw"]));
		while ($row = $statement->fetch()) {
			if ($row["username"] === $_POST["uname"] && $row["password"] === $_POST["pw"]) {
				$_SESSION["login"] = "true";
				$_SESSION["username"] = $row["username"];
				$login_failed = false;
			}
		}
	} elseif (isset($_POST["logout_submit"])) {
		// Logout:
		$_SESSION["login"] = "false";
		$_SESSION["username"] = "";
	} elseif (isset($_POST["post_message_submit"]) && isset($_SESSION["login"]) && $_SESSION["login"] == "true") {
		// Add posted message to DB:
		$statement = $db->prepare("INSERT INTO messages(id, username, ip_addr, message, timestmp) VALUES ((SELECT IFNULL(MAX(id)+1, 0) FROM (SELECT * FROM messages) AS m), ?, ?, ?, CURRENT_TIMESTAMP)");
		$statement->execute(array($_SESSION["username"], $_SERVER['REMOTE_ADDR'], substr(preg_replace("/[^a-zA-Z0-9 _\-.,;]/i", "", $_POST["message"]), 0, 64)));
	}
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<meta http-equiv="Content-Security-Policy" content="script-src 'none'; form-action 'self';" />
		<title>xsrf.me</title>
		<style type="text/css">
			table, th, td {
				border: 1px solid black;
			}
		</style>
	</head>
	<body style="height:100%;font-family:Arial,Helvetica,sans-serif;">
		<div style="display:flex;justify-content:center;align-items:center;height:100%;">
			<div>
				<div>
					<h1 style="font-size: 5em; text-align: center;">xsrf.me</h1>
				</div>
				<div style="border-style: solid; padding: 15px 15px;">
					<span style="font-weight: bold;">This site is <a href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">XSRF</a>-vulnerable, try it out!</span>
				</div>
				<br/>
				<br/>
				<div style="border-style: solid; padding: 15px 15px;">
					<?php
						if (isset($_SESSION["login"]) && $_SESSION["login"] === "true") {
							echo "<p>You are logged in as: " . htmlentities($_SESSION["username"]);
							echo "<form action=\"index.php\" method=\"POST\"><input type=\"submit\" name=\"logout_submit\" value=\"Logout\" /></form></p>";
						} else {
							echo "<form action=\"index.php\" method=\"POST\">
									<label for=\"uname\">Username: </label><input type=\"text\" id=\"uname\" name=\"uname\" /><br/>
									<label for=\"pw\">Password: </label><input type=\"password\" id=\"pw\" name=\"pw\" /><br/>
									<input type=\"submit\" name=\"login_submit\" value=\"Login\" />
								</form>";
							if ($login_failed) {
								echo "<span style=\"color:red\">Login failed!</span>";
							}
						}
					?>
					<p>
						<i>Hint: Users of this website are all former U.S. presidents (username: last name, password: year of birth).</i>
					</p>
				</div>
				<br/>
				<br/>
				<div style="border-style: solid; padding: 15px 15px;">
					<h2>Message Board:</h2>
					<p>
						<?php
							if (isset($_SESSION["login"]) && $_SESSION["login"] === "true") {
								echo "<form action=\"index.php\" method=\"POST\">
									<label for=\"message\">Message: </label><input type=\"text\" id=\"message\" name=\"message\" />
									<input type=\"submit\" name=\"post_message_submit\" value=\"Post message\" />
								</form>";
							} else {
								echo "<span id=\"you_need_to_be_logged_in_span\" style=\"font-style: italic;\">You need to be logged in in order to post messages!</span>";
							}
						?>
					</p>
					<table width="100%">
						<tr>
							<th>User</th>
							<th>Message</th>
						</tr>
						<?php
						$statement = $db->prepare("SELECT * FROM messages ORDER BY id DESC");
						$statement->execute();
						while ($row = $statement->fetch()) {
							echo "<tr><td>" . htmlentities($row["username"]) . " <i>(" . htmlentities($row["ip_addr"]) . ")</i></td><td>" . htmlentities($row["message"]) . "</td></tr>";
						}
						?>
					</table>
					<p>
						<i>Note: Messages older than 1 hour are deleted automatically.</i>
					</p>
				</div>
				<br/>
				© 2023 Kendrick Grünberg | <a href="https://github.com/k-gruenberg/xsrf.me">View source code</a>
			</div>
		</div>
	</body>
</html>
<?php
	// Remove messages older than 1 hour from the DB:
	$statement = $db->prepare("DELETE FROM messages WHERE TIMESTAMPDIFF(SECOND, timestmp, CURRENT_TIMESTAMP) > 3600");
	$statement->execute();
?>
