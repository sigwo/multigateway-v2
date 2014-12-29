<?php
 header("Access-Control-Allow-Origin: *");

/*if(isset($_GET["requestType"]) && $_GET["requestType"] == "echo")
{
	// now were in buisness
	$ret = new STDClass();
	$ret->result = "success";
	$ret->echo = shell_exec("./newbie ".$_GET["msg"]);
	echo json_encode($ret);
}
else 
{
	$ret = new STDClass();
	$ret->result = "failure";
	echo json_encode($ret);
}*/


	$jsoned = json_encode($_GET);
	set_time_limit(10);
	echo shell_exec("./SuperNET '".$jsoned."'");
?>
