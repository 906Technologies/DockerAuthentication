<?php
use Firebase\JWT\JWT;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ParameterBag;
use Silex\Application;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;

require_once __DIR__.'/vendor/autoload.php';

try {
	$config = Yaml::parse(file_get_contents('config.yml'));
} catch (ParseException $e) {
    die('Unable to parse config.yml');
}

$app = new Application();

$privateKeyContents = file_get_contents($config['private_key']);
$privateKey = openssl_pkey_get_private($privateKeyContents);

$kid = getKid($privateKey);

function getKid($privateKey){
	$details = openssl_pkey_get_details($privateKey);
	
	$publicKey = str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'], '', $details['key']);
	$publicKey = trim($publicKey);
	$der = base64_decode($publicKey);
	
	$hashDer = hash('sha256', $der, true);
	
	$first30bytes = substr($hashDer, 0, 30);
	
	$libtrust = Base32\Base32::encode($first30bytes);
	
	$chunks = [];

	for ($i = 0, $max = 48; $i < $max; $i += 4) {
		$chunk = substr($libtrust, $i, 4);
		$chunks[] = $chunk;
	}
	
	$fingerprint = implode(":", $chunks);
	
	return $fingerprint;
}

$log = new Logger('name');
$log->pushHandler(new StreamHandler('auth.log', Logger::INFO));

//$app['debug'] = true;

function pamAuthenticate($user, $password){
	if (!$user || !$password || strlen($user) > 30 || strlen($password) > 60){
		throw new \Exception ('Missing Creds');
	}

	$error = '';
	$blacklistedUsers = array('elegantseagulls'); //k

	if (in_array($user, $blacklistedUsers) || !pam_auth($user, $password, $error, false)) {
		throw new \Exception ('Pam Authenticaiton Failed : '.$error);
	}
	return true;
}
 
$app->get('/', function (Request $request) {
	return  "<h1>This is not the auth you are looking for</h1>";
});
	
$app->get('/docker/v2/token', function (Request $request) use ($app, $privateKey, $log, $kid, $config) {
	JWT::$leeway = 60; // $leeway in seconds
	$log->info('Requested', [$request->getUri()]);
	
	$authorizationHeader = $request->headers->get('authorization');
	
	if(!$authorizationHeader){
		$log->error('Missing authorization Header', []);
		return$app->json(
			["errors" => [
				"code" => "UNAUTHORIZED"
				]
			], 401);
	}
	
	if (strpos($authorizationHeader, "Basic") === 0){
		$log->info('Token Requested', []);
		$log->info('Params', $request->query->all());
		
		$credentialsEncoded = str_replace('Basic ', '', $authorizationHeader);
		list($user, $password) = explode(':', base64_decode($credentialsEncoded), 2);
		
		$log->info('User', ["username"=>$user]);
		
		try{
			pamAuthenticate($user, $password);
			
			$expires = strtotime('+3 day', time());
			$token = array(
				"iss" => $config["issuer"],
				"aud" => $config["audience"],
				"iat" => time(),
				"nbf" => time(),
				"exp" => $expires,
				"sub" => $user,
				"jti" => uniqid(),
				"user" => $user
			);
			$scope = $request->query->get('scope');
			
			if($scope){
				list($type, $name, $actions) = explode(":", $scope, 3);
				$actions = explode(",", $actions);
				
				$token['access'] = [[
					'type' => $type,
					'name' => $name,
					'actions' => $actions
				]];
			}
			
			$now = new \DateTime();
			
			$log->info('Response Claims Created', $token);
			
			$response = [
				'token' => JWT::encode($token, $privateKey, 'RS256', $kid),
				'expires_in' => ($expires - time()),
				'issued_at' => $now->format(\DateTime::RFC3339)];
		
			
			//$log->info('Authentication Response', $response);
			
			return $app->json($response, 200, array());
				
		} catch (\Exception $e){
			$log->error('Validation Error: '.$e->getMessage(), []);
			return $app->json('Invalid Credentials', 403);
		}
		
	} else if (strpos($authorizationHeader, "Bearer") === 0){ 
		//this will never get hit because docker has the public key and can varify the validity of the token itself
		//none the less its still good to have for testing if tokens generated can be verified by the public key
		
		$log->info('TOKEN VERIFICATION', []);
		
		$token = str_replace('Bearer ', '', $authorizationHeader);
		
		try{
			$details = openssl_pkey_get_details($privateKey);
			$publicKey = openssl_pkey_get_public($details['key']);
			$payload = JWT::decode($token, $publicKey, array('RS256'));
		} catch (\Firebase\JWT\ExpiredException $e){
			$log->error('Token Expired', []);
			return $app->json('Invalid Token', 403);
		} catch (\Exception $e){
			$log->error('Token Verification Error: '.$e->getMessage(), []);
			return $app->json('Invalid Token', 403);
		}
		
		return $app->json([], 200, array());
	}


	
	$log->error("End point hit however no auth request or verification was made.",[]);
	
	return $app->json(
		["errors" => [
			"code" => "UNAUTHORIZED"
		]
		], 401);
});

$app->run();


/*
//attempt at geting docker registry to accept x5c claim in the header, correct formating done here but still untrusted by registry 
$fullChainContents = file_get_contents("/path/to/fullchain.pem");
$x5c = explodeChain($fullChainContents);
function explodeChain($chainContents){
	$chainLines = explode("\n", $chainContents);
	//print_r($chainLines);
	$x5c = [];
	$lines = [];
	foreach($chainLines as $chainLine){
		if(strlen($chainLine) == 0 || strpos($chainLine, "-----BEGIN") === 0){
			continue;
		}

		if(strpos($chainLine, "-----END") === 0){
			$chainLink = implode("", $lines);
			$x5c[] = $chainLink;//base64_encode($chainLink);
			$lines = [];
		} else {
			$lines[] = $chainLine;
		}
	}
	return $x5c;
}*/