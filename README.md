# infra-stack-cdk-snippet

AWS CDK stack snippet for base app deployment (NodeJS/Redis/Postgres)

## Usage

```typescript

  #!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { InfraStack } from "../lib/infra-stack";
import { ECRRepoStack } from "../lib/ecr-repo";
import { ExtendedStackProps } from "../lib/base-stack";
import { SharedStack } from "../lib/shared-stack";

global.Error.stackTraceLimit = 100;

const resourcePrefix = process.env.AWS_DEPLOY_RESOURCE_PREFIX;

const props: ExtendedStackProps = {
  env: {
    account: process.env.AWS_ACCOUNT_ID,
    region: process.env.AWS_DEFAULT_REGION,
    appName: process.env.APP_NAME,
    appDomainName: process.env.APP_DOMAIN_NAME,
    sesEmailFrom: process.env.SES_EMAIL_FROM,
    certificateId: process.env.CERTIFICATE_ID,
    domainName: process.env.DOMAIN_NAME,
    domainZoneId: process.env.DOMAIN_ZONE_ID,
    domainZoneName: process.env.DOMAIN_ZONE_NAME,
    session: process.env.CURRENT_AWS_USER,
    lambdaAppName: process.env.LAMBDA_APP_NAME,
    commitSHA: process.env.CI_COMMIT_SHORT_SHA,
    dropAndCreate: process.env.DROP_AND_CREATE === "true",
  },
};

const app = new cdk.App();

const sharedStack = new SharedStack(app, `${resourcePrefix}Shared`, props);
sharedStack.createResources();

const ecrRepoStack = new ECRRepoStack(app, `${resourcePrefix}Code`, props);
ecrRepoStack.setVPC(sharedStack.getVPC()!);
ecrRepoStack.addDependency(sharedStack);
ecrRepoStack.createResources();

const infraStack = new InfraStack(app, `${resourcePrefix}Infra`, props);
infraStack.setVPC(sharedStack.getVPC()!);
infraStack.setAPIRepository(ecrRepoStack.getAPIRepository());
infraStack.setPreDeploymentMigrationLambdaRepository(
  ecrRepoStack.getPreDeploymentMigrationLambdaRepository()
);
infraStack.addDependency(sharedStack);
infraStack.addDependency(ecrRepoStack);
infraStack.createResources();

console.log(`


                  !!!SUCCESS!!! 
       CloudFormation instructions generated.

       
`);


```

## Author

@arpad1337

## License

MIT

