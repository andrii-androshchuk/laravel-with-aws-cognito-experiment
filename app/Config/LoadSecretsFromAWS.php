<?php

namespace App\Config;

use Aws\SecretsManager\SecretsManagerClient;
use Illuminate\Foundation\Application;
use Illuminate\Support\Arr;
use Illuminate\Support\Env;
use Illuminate\Support\Str;
use Symfony\Component\Console\Input\ArgvInput;

final readonly class LoadSecretsFromAWS
{
    public function __construct(
        private Application $app,
        private string $prefix,
        private array $environments = ['production']) {}

    /**
     * Get the correct environment and load appropriate secrets from AWS Secrets Manager.
     */
    public function __invoke(): void
    {
        if ($this->app->configurationIsCached()) {
            return;
        }

        $environment = ($this->app->runningInConsole() && ($input = new ArgvInput)->hasParameterOption('--env'))
            ? $input->getParameterOption('--env')
            : Env::get('APP_ENV');

        if (in_array($environment, $this->environments, true)) {

            $this->loadSecrets($this->prefix.'/'.$environment.'/');
        }
    }

    /**
     * Load variables from AWS Secrets Manager for the given prefix and store them in the environment.
     */
    private function loadSecrets(string $prefix): void
    {
        $client = $this->createSecretsManagerClient();

        $secrets = $this->getListOfSecrets($client, $prefix);

        $values = $this->getSecretValues($client, $secrets);

        $this->setEnvironmentVariables($values, $prefix);
    }

    /**
     * Create a new instance of SecretsManagerClient to interact with AWS Secrets Manager.
     */
    private function createSecretsManagerClient(): SecretsManagerClient
    {
        return new SecretsManagerClient([
            'region' => env('AWS_REGION'),
            'version' => 'latest',
            'credentials' => [
                'key' => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);
    }

    /**
     * Set environment variables from the given list of variables.
     */
    private function setEnvironmentVariables($variables, $prefix): void
    {
        $repository = Env::getRepository();

        foreach ($variables as $key => $value) {

            $repository->set(Str::after($key, $prefix), $value);
        }
    }

    /**
     * Get list of secrets from AWS Secrets Manager, filtered by prefix.
     */
    private function getListOfSecrets(SecretsManagerClient $client, string $prefix): array
    {
        $secrets = [];
        $nextToken = null;

        do {

            $arguments = [
                'Filters' => [
                    [
                        'Key' => 'name',
                        'Values' => ["{$prefix}"],
                    ],
                ],
            ];

            if ($nextToken) {

                $arguments['NextToken'] = $nextToken;
            }

            $data = $client->listSecrets($arguments);

            throw_unless(Arr::get($data['@metadata'], 'statusCode') === 200,
                new \Exception('Failed to get list of secrets from AWS Secrets Manager'));

            $secrets = array_merge($secrets, array_map(fn ($secret) => $secret['Name'], $data['SecretList']));

            $nextToken = $data['NextToken'];

        } while ($nextToken);

        return $secrets;
    }

    /**
     * Get secret value from AWS Secrets Manager for each secret in the list.
     */
    private function getSecretValues(SecretsManagerClient $client, array $secrets): array
    {
        $values = [];
        $nextToken = null;

        do {

            $arguments = [
                'SecretIdList' => $secrets,
            ];

            if ($nextToken) {

                $arguments['NextToken'] = $nextToken;
            }

            $data = $client->batchGetSecretValue($arguments);

            throw_unless(Arr::get($data['@metadata'], 'statusCode') === 200,
                new \Exception('Failed to get secret value from AWS Secrets Manager'));

            foreach ($data['SecretValues'] as $secret) {

                $values[$secret['Name']] = $secret['SecretString'];
            }

            $nextToken = $data['NextToken'];

        } while ($nextToken);

        return $values;
    }
}
