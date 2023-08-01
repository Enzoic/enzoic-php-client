<?php

namespace Enzoic\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Enzoic\Enzoic;

class EnzoicTest extends TestCase
{
    protected function setUp(): void
    {
    }

    public function testConstructor()
    {
        $enzoic = new Enzoic(getenv('PP_API_KEY'), getenv('PP_API_SECRET'));

        $settings = $enzoic->getSettings();
        $this->assertEquals(getEnv('PP_API_KEY'), $settings['api_key']);
        $this->assertEquals(getEnv('PP_API_SECRET'), $settings['secret']);
        $this->assertEquals('api.enzoic.com', $settings['api_host']);
        $this->assertEquals('https://api.enzoic.com/v1', $settings['api_url']);

        //echo(crypt('12345', '$2a$12$2bULeXwv2H34SXkT1giCZe'));
        //echo(crypt('123456789', '$H$993WP3hbz'));
        //echo('<br/>');
        //echo(exec('echo -n "password" | argon2 "4zU7iIzt6Ej+PH[ol+ir7i\!Y*K-d90DB" -d -t 2 -k 1024 -p 2 -l 20 -e'));
    }

    public function testCheckPassword()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->checkPassword('kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd');
        $this->assertEquals(null, $response);

        $response = $enzoic->checkPassword('``--...____...--\'\'');
        $this->assertEquals($response, [
            'revealedInExposure' => false,
            'relativeExposureFrequency' => 0
        ]);

        $response = $enzoic->checkPassword('123456');
        $this->assertEquals($response, [
            'revealedInExposure' => true,
            'relativeExposureFrequency' => 9
        ]);
    }

    public function testCheckCredentials()
    {
        $enzoic = $this->getEnzoic();

        for ($i = 1; $i <= 36; $i++) {
            if (in_array($i, [4, 9, 11, 12, 14])) continue;

            echo "testing" . $i . "\n";

            $response = $enzoic->checkCredentials('eicar_' . $i . '@enzoic.com', '123456');

            $this->assertEquals(true, $response);
        }
    }

    public function testGetExposuresForUser()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->getExposuresForUser('@@bogus-username@@');
        $this->assertEquals([], $response);

        $response = $enzoic->getExposuresForUser('eicar');
        $this->assertEquals([
            "5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479", "59ba1aa369644815dcd8683e", "59cae0ce1d75b80e0070957c", "5bc64f5f4eb6d894f09eae70", "5bdcb0944eb6d8a97cfacdff"
        ], $response);
    }

    public function testGetExposureDetails()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->getExposureDetails('111111111111111111111111');
        $this->assertEquals(NULL, $response);

        $response = $enzoic->getExposureDetails('5820469ffdb8780510b329cc');
        $this->assertEquals((object)[
            'id' => '5820469ffdb8780510b329cc',
            'title' => 'last.fm',
            'entries' => 81967007,
            'date' => '2012-03-01T00:00:00.000Z',
            'category' => 'Music',
            'passwordType' => 'MD5',
            'exposedData' => [
                'Emails',
                'Passwords',
                'Usernames',
                'Website Activity'
            ],
            'dateAdded' => '2016-11-07T09:17:19.000Z',
            'sourceURLs' => [],
            'domainsAffected' => 1219053,
            'source' => 'Unspecified',
            'sourceFileCount' => 1
        ], $response);
    }

    public function testGetPasswordsForUser()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->getPasswordsForUser('@@bogus-username@@');
        $this->assertEquals(null, $response);

        $response = $enzoic->getPasswordsForUser('eicar_0@enzoic.com');
        $this->assertEquals((object)[
            'lastBreachDate' => '2022-10-14T07:02:40.000Z',
            'passwords' => [
                (object)[
                    'password' => 'password123',
                    'hashType' => 0,
                    'salt' => '',
                    'exposures' => ['634908d2e0513eb0788aa0b9','634908d06715cc1b5b201a1a']
                ],
                (object)[
                    'password' => 'g0oD_on3',
                    'hashType' => 0,
                    'salt' => '',
                    'exposures' => ['634908d2e0513eb0788aa0b9']
                ],
                (object)[
                    'password' => 'Easy2no',
                    'hashType' => 0,
                    'salt' => '',
                    'exposures' => ['634908d26715cc1b5b201a1d']
                ],
                (object)[
                    'password' => '123456',
                    'hashType' => 0,
                    'salt' => '',
                    'exposures' => ['63490990e0513eb0788aa0d1','634908d0e0513eb0788aa0b5']
                ],
            ]
        ], $response);

        $response = $enzoic->getPasswordsForUser('eicar_8@enzoic.com', true);
        $this->assertEquals((object)[
            'lastBreachDate' => '2017-04-08T02:07:44.000Z',
            'passwords' => [
                (object)[
                    'password' => '$2a$04$yyJQsNrcBeTRgYNf4HCTxefTL9n7rFYywPxdXU9YRRTgkaZaNkgyu',
                    'hashType' => 8,
                    'salt' => '$2a$04$yyJQsNrcBeTRgYNf4HCTxe',
                    'exposures' => [
                        (object)[
                            'id' => '58e845f04d6db222103001df',
                            'title' => 'passwordping.com test breach BCrypt',
                            'entries' => 1,
                            'date' => '2010-01-01T07:00:00.000Z',
                            'category' => 'Testing Ignore',
                            'source' => 'Testing - Ignore',
                            'passwordType' => 'BCrypt',
                            'exposedData' => [
                                'Emails', 'Passwords'
                            ],
                            'dateAdded' => '2017-04-08T02:07:44.000Z',
                            'sourceURLs' => [],
                            'sourceFileCount' => 1,
                            'domainsAffected' => 1                        ]
                    ]
                ]
            ]
        ], $response);
    }

    private function getEnzoic()
    {
        return new Enzoic(getenv('PP_API_KEY'), getenv('PP_API_SECRET'));
    }
}