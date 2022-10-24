# Enzoic PHP Client Library

## TOC

This README covers the following topics:

- [Installation](#installation)
- [API Overview](#api-overview)
- [The Enzoic constructor](#the-enzoic-constructor)

## Installation

To include the Enzoic library in your project using Composer: 

```sh
$ composer require enzoic/enzoic
```


**Enzoic for PHP requires the Argon2 command line utility to be installed and runnable by your PHP application.  See [https://github.com/P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) for installation instructions.**

## API Overview

Below is some simple example code which demonstrates the usage of the API. 

```php
<?php

use Enzoic\Enzoic;
use Enzoic\PasswordType;

// Create a new Enzoic instance - this is our primary interface for making API calls
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);

// Check whether a password has been compromised
// see https://www.enzoic.com/docs-passwords-api/ for more information
$passwordCompromised = $enzoic->checkPassword('password-to-test'); 

if ($passwordCompromised === true) {
    echo 'Password is compromised';
}
else {
    echo 'Password is not compromised';
}

// Check whether a specific set of credentials are compromised
// see https://www.enzoic.com/docs-credentials-api/ for more information
$credentialsCompromised = $enzoic->checkCredentials('test@enzoic.com', 'password-to-test'); 

 if ($credentialsCompromised === true) {
    echo 'Credentials are compromised';
}
else {
    echo 'Credentials are not compromised';
}

// checkCredentials has optional parameters offering more control over performance.
//
// lastCheckDate: 
// A DateTime containing the timestamp of the last credentials check you performed for this user.
// If the date/time you provide for the last check is greater than the timestamp Enzoic has for the last
// breach affecting this user, the check will not be performed.  This can be used to substantially increase performance 
// after the initial call.
//
// excludeHashAlgorithms: 
// An array of PasswordTypes to ignore when calculating hashes for the credentials check.   
// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this
// call against security.
//

// should be set to the last time you checked credentials for this user for performance
$dateOfLastCredentialsCheck = new DateTime('2020-07-01T02:05:03.000Z');

// let's exclude BCrypt and PHPBB3 
$excludeHashAlgorithms = [ PasswordType::BCrypt, PasswordType::PHPBB3 ];

$credentialsCompromised = $enzoic->checkCredentials('test@enzoic.com', 'password-to-test', 
    $dateOfLastCredentialsCheck, $excludeHashAlgorithms);
    
if ($credentialsCompromised === true) {
    echo 'Credentials are compromised';
}
else {
    echo 'Credentials are not compromised';
}

// get all exposures for the given user
// see https://www.enzoic.com/docs-exposures-api/#get-exposures for more information
$userExposures = $enzoic->getExposuresForUser('eicar_1@enzoic.com');

echo count($userExposures).' exposures found for eicar_1@enzoic.com';
    
// now get the full details for the first exposure returned in the list
// see https://www.enzoic.com/docs-exposures-api/#get-exposure-details for more information
$exposureDetails = $enzoic->getExposureDetails($userExposures[0]);

echo 'First exposure for test@enzoic.com was '.$exposureDetails->{'title'};

// get all passwords for a given user - requires special approval, contact Enzoic sales
// see https://www.enzoic.com/docs-raw-passwords-api/ for more information
$userPasswords = $enzoic->getPasswordsForUser("eicar_0@enzoic.com");
echo "First password for eicar_0@enzoic.com was ".$userPasswords->{'passwords'}[0]->{'password'};

?>
```

More information in reference format can be found below.

## The Enzoic constructor

The standard constructor takes the API key and secret you were issued on Enzoic signup.

```php
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API host, you may call the overloaded constructor and pass the host you were provided.

```php
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET, "api-alt.enzoic.com");
```
