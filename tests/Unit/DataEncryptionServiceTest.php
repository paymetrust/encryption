<?php

namespace Paymetrust\LaravelDataEncryption\Tests\Unit;

use Dotenv\Dotenv;
use RuntimeException;
use Orchestra\Testbench\TestCase;
use Paymetrust\LaravelDataEncryption\Services\DataEncryptionService;

class DataEncryptionServiceTest extends TestCase
{
    private DataEncryptionService $dataEncryptionService;
    private string $publicKeyPath;
    private string $privateKeyPath;

    private string $originalData;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dataEncryptionService = new DataEncryptionService();
    }

    protected function getEnvironmentSetUp($app)
    {
        $dotenv = Dotenv::createImmutable(__DIR__ , '.env.testing');
        $dotenv->load();

        $this->publicKeyPath = env('SSL_PUBLIC_KEY_PATH');
        $this->privateKeyPath = env('SSL_PRIVATE_KEY_PATH');
        $this->originalData = json_encode(['test' => 'data']);

        if (is_null($this->publicKeyPath) || is_null($this->privateKeyPath)) {
            throw new RuntimeException('Les chemins de clés ne sont pas définis correctement.');
        }
    }

    public function testEncrypt()
    {
        $encryptedData = $this->dataEncryptionService->encrypt($this->originalData, $this->publicKeyPath);
        $this->assertNotEmpty($encryptedData, 'Encryption failed, result is empty.');
        return $encryptedData;
    }

    /**
     * @depends testEncrypt
     */
    public function testDecrypt(string $encryptedData)
    {
        $decryptedData = $this->dataEncryptionService->decrypt($encryptedData, $this->privateKeyPath);
        $this->assertEquals($this->originalData, $decryptedData, 'Decryption did not return the original data.');
    }

    public function testDecryptWithInvalidPublicKey()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid private key.');

        $this->dataEncryptionService->decrypt($this->originalData, $this->publicKeyPath);
    }

    public function testEncryptWithInvalidPrivateKey()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid public key.');

        $this->dataEncryptionService->encrypt($this->originalData, $this->privateKeyPath);
    }

    public function testDecryptWithInvalidData()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to decrypt data.');

        $encryptedData = base64_encode(json_encode(['testNo' => 'dataNo']));
        $this->dataEncryptionService->decrypt($encryptedData, $this->privateKeyPath);
    }
}
