import * as cdk from "aws-cdk-lib";
import * as EC2 from "aws-cdk-lib/aws-ec2";
import * as ECS from "aws-cdk-lib/aws-ecs";
import * as IAM from "aws-cdk-lib/aws-iam";
import * as CM from "aws-cdk-lib/aws-certificatemanager";
import * as ElastiCache from "aws-cdk-lib/aws-elasticache";
import * as RDS from "aws-cdk-lib/aws-rds";
import * as SecretsManager from "aws-cdk-lib/aws-secretsmanager";
import * as Logs from "aws-cdk-lib/aws-logs";
import * as ECSPatterns from "aws-cdk-lib/aws-ecs-patterns";
import * as Lambda from "aws-cdk-lib/aws-lambda";
import * as CustomResources from "aws-cdk-lib/custom-resources";
import * as ECR from "aws-cdk-lib/aws-ecr";
import { BaseStack } from "./base-stack";
import {
  ApplicationProtocol,
  SslPolicy,
} from "aws-cdk-lib/aws-elasticloadbalancingv2";
import { PublicHostedZone } from "aws-cdk-lib/aws-route53";
import { Construct } from "constructs";
import * as codepipeline from "aws-cdk-lib/aws-codepipeline";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import * as codepipelineActions from "aws-cdk-lib/aws-codepipeline-actions";
import * as pipelines from "aws-cdk-lib/pipelines";

export class InfraStack extends BaseStack {
  protected dockerImageAssetRepository: ECR.IRepository | undefined = undefined;

  setAPIRepository(image: ECR.IRepository | undefined): void {
    this.dockerImageAssetRepository = image;
  }

  protected preDeploymentMigrationLambdaImageAssetRepository:
    | ECR.IRepository
    | undefined = undefined;

  setPreDeploymentMigrationLambdaRepository(
    image: ECR.IRepository | undefined
  ): void {
    this.preDeploymentMigrationLambdaImageAssetRepository = image;
  }

  createResources(): void {
    const dbPort = 5432;
    const redisPort = 6379;
    const appPort = 8100;

    const vpc = this.vpc!;

    const fargateExternalSecurityGroup = new EC2.SecurityGroup(
      this,
      `${this.resourcePrefix}FargateExternalSecurityGroup`,
      {
        vpc: vpc,
        allowAllOutbound: false,
      }
    );

    fargateExternalSecurityGroup.addIngressRule(
      EC2.Peer.anyIpv4(),
      EC2.Port.tcp(443),
      `Allow inbound traffic from anywhere from the internet to the Load Balancer on port 443`
    );

    const fargateInternalSecurityGroup = new EC2.SecurityGroup(
      this,
      `${this.resourcePrefix}FargateInternalSecurityGroup`,
      {
        vpc: vpc,
        allowAllOutbound: true,
      }
    );

    fargateInternalSecurityGroup.addIngressRule(
      EC2.Peer.ipv4(vpc.vpcCidrBlock),
      EC2.Port.tcp(appPort),
      `Allow inbound traffic from anywhere within the VPC to the app on port ${appPort}`
    );

    const auroraSecurityGroup = new EC2.SecurityGroup(
      this,
      `${this.resourcePrefix}AuroraSecurityGroup`,
      {
        vpc: vpc,
        allowAllOutbound: false,
      }
    );

    auroraSecurityGroup.addIngressRule(
      EC2.Peer.ipv4(vpc.vpcCidrBlock),
      EC2.Port.tcp(dbPort),
      `Allow inbound traffic from anywhere within the VPC to the db on port ${dbPort}`
    );

    auroraSecurityGroup.addEgressRule(
      EC2.Peer.ipv4(vpc.vpcCidrBlock),
      EC2.Port.allTraffic(),
      `Allow outbound traffic from the db within the VPC`
    );

    const dbSecret = SecretsManager.Secret.fromSecretNameV2(
      this,
      `${this.resourcePrefix}SecretsDatabase`,
      "DATABASE_PROD"
    );

    const dbName = "production";

    const databaseCluster = new RDS.DatabaseCluster(
      this,
      `${this.resourcePrefix}AuroraCluster`,
      {
        vpc: vpc,
        securityGroups: [auroraSecurityGroup],
        vpcSubnets: vpc.selectSubnets({
          subnetType: EC2.SubnetType.PRIVATE_WITH_EGRESS, // hmm...
        }),
        clusterIdentifier: `${this.resourcePrefix}Aurora`,
        engine: RDS.DatabaseClusterEngine.auroraPostgres({
          version: RDS.AuroraPostgresEngineVersion.VER_15_4,
        }),
        credentials: RDS.Credentials.fromSecret(dbSecret),
        defaultDatabaseName: dbName,
        port: dbPort,
        storageEncrypted: true,
        writer: RDS.ClusterInstance.serverlessV2("WriteAndReadInstance"),
        readers: [
          RDS.ClusterInstance.serverlessV2("ReadOnlyInstance", {
            scaleWithWriter: true,
          }),
        ],
        backup: {
          preferredWindow: "00:00-01:00",
          retention: cdk.Duration.days(30),
        },
        deletionProtection: false,
        cloudwatchLogsRetention: Logs.RetentionDays.ONE_WEEK,
      }
    );

    cdk.Aspects.of(databaseCluster).add({
      visit(node: RDS.CfnDBCluster | any) {
        if (node instanceof RDS.CfnDBCluster) {
          node.serverlessV2ScalingConfiguration = {
            minCapacity: 0.5,
            maxCapacity: 2,
          };
        }
      },
    });

    const redisSecurityGroup = new EC2.SecurityGroup(
      this,
      `${this.resourcePrefix}ElastiCacheSecurityGroup`,
      {
        vpc: vpc,
        allowAllOutbound: false,
      }
    );

    redisSecurityGroup.addIngressRule(
      EC2.Peer.ipv4(vpc.vpcCidrBlock),
      EC2.Port.tcp(redisPort),
      `Allow inbound traffic from anywhere within the VPC to the cache on port ${redisPort}`
    );

    redisSecurityGroup.addEgressRule(
      EC2.Peer.ipv4(vpc.vpcCidrBlock),
      EC2.Port.allTraffic(),
      `Allow outbound traffic from the cache within the VPC`
    );

    const subnetsForRedis = vpc.selectSubnets({
      subnetType: EC2.SubnetType.PRIVATE_WITH_EGRESS, // hmm...
    }).subnetIds;

    const redisSubnetGroup = new ElastiCache.CfnSubnetGroup(
      this,
      `${this.resourcePrefix}ElastiCacheReplicationSubnetGroup`,
      {
        cacheSubnetGroupName: `${this.resourcePrefix}ElastiCacheReplicationSubnetGroup`,
        subnetIds: subnetsForRedis,
        description: `Redis subnet group`,
      }
    );

    const redisSecret = SecretsManager.Secret.fromSecretNameV2(
      this,
      `${this.resourcePrefix}SecretsCache`,
      "CACHE_PROD"
    );

    const redisCluster = new ElastiCache.CfnReplicationGroup(
      this,
      `${this.resourcePrefix}ElastiCacheReplicationGroup`,
      {
        authToken: redisSecret
          .secretValueFromJson("auth")
          .unsafeUnwrap()
          .toString(),
        replicationGroupId: `${this.resourcePrefix}ElastiCache`,
        replicationGroupDescription: "Redis replication group",
        atRestEncryptionEnabled: true,
        multiAzEnabled: true,
        cacheNodeType: "cache.t2.micro",
        cacheSubnetGroupName: redisSubnetGroup.cacheSubnetGroupName,
        engine: "Redis",
        engineVersion: "6.x",
        numNodeGroups: 1,
        replicasPerNodeGroup: 2,
        securityGroupIds: [redisSecurityGroup.securityGroupId],
        transitEncryptionEnabled: true,
      }
    );

    redisCluster.node.addDependency(redisSubnetGroup);

    const taskRole = new IAM.Role(
      this,
      `${this.resourcePrefix}FargateTaskRole`,
      {
        assumedBy: new IAM.ServicePrincipal("ecs-tasks.amazonaws.com"),
      }
    );

    const executionRole = new IAM.Role(
      this,
      `${this.resourcePrefix}FargateTaskExecutionRole`,
      {
        assumedBy: new IAM.ServicePrincipal("ecs-tasks.amazonaws.com"),
      }
    );

    executionRole.addManagedPolicy(
      IAM.ManagedPolicy.fromAwsManagedPolicyName(
        "service-role/AmazonECSTaskExecutionRolePolicy"
      )
    );

    executionRole.addManagedPolicy(
      IAM.ManagedPolicy.fromAwsManagedPolicyName(
        "AmazonEC2ContainerRegistryPowerUser"
      )
    );

    const taskDefinition = new ECS.FargateTaskDefinition(
      this,
      `${this.resourcePrefix}FargateTask`,
      {
        taskRole: taskRole,
        executionRole: executionRole,
        cpu: 512,
        memoryLimitMiB: 1024,
      }
    );

    const encryptionSecret = SecretsManager.Secret.fromSecretNameV2(
      this,
      `${this.resourcePrefix}SecretsEncryption`,
      "ENCRYPTION_PROD"
    );

    const sesSecret = SecretsManager.Secret.fromSecretNameV2(
      this,
      `${this.resourcePrefix}SecretsSES`,
      "SES_PROD"
    );

    const container: ECS.ContainerDefinitionOptions = {
      containerName: this.env.appName!,
      image: ECS.ContainerImage.fromEcrRepository(
        this.dockerImageAssetRepository!,
        this.env.commitSHA
      ),
      healthCheck: {
        command: [
          "CMD-SHELL",
          `wget -nv -t1 --spider 'http://localhost:${appPort.toString()}/common/status' || exit 1`,
        ],
        interval: cdk.Duration.minutes(1),
        timeout: cdk.Duration.minutes(1),
        retries: 3,
        startPeriod: cdk.Duration.seconds(10),
      },
      portMappings: [
        {
          containerPort: appPort,
          hostPort: appPort,
          protocol: ECS.Protocol.TCP,
        },
      ],
      logging: ECS.LogDrivers.awsLogs({
        streamPrefix: `${this.resourcePrefix}FargateTaskLogs`,
        logRetention: Logs.RetentionDays.ONE_WEEK,
      }),
      secrets: {
        DATABASE_PASSWORD: ECS.Secret.fromSecretsManager(dbSecret, "password"),
        DATABASE_USERNAME: ECS.Secret.fromSecretsManager(dbSecret, "username"),
        REDIS_AUTH: ECS.Secret.fromSecretsManager(redisSecret, "auth"),
        PASSWORD_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "password_salt"
        ),
        PASSWORD_IN_TRANSMIT_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "password_in_transmit_salt"
        ),
        SESSION_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "session_salt"
        ),
        ADAPTER_LOCK_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "adapter_lock_salt"
        ),
        SESSION_KEY: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "session_key"
        ),
        OTP_CODE_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "otp_code_salt"
        ),
        API_CREDENTIAL_SECRET_SALT: ECS.Secret.fromSecretsManager(
          encryptionSecret,
          "api_credential_secret_salt"
        ),
        SES_ACCESS_KEY: ECS.Secret.fromSecretsManager(
          sesSecret,
          "ses_access_key"
        ),
        SES_SECRET_ACCESS_KEY: ECS.Secret.fromSecretsManager(
          sesSecret,
          "ses_secret_access_key"
        ),
      },
      environment: {
        PORT: appPort.toString(),
        NODE_ENV: "production",
        DATABASE_HOST: databaseCluster.clusterEndpoint.hostname,
        DATABASE_PORT: databaseCluster.clusterEndpoint.port.toString(),
        DATABASE_DATABASE: dbName,
        REDIS_HOST: redisCluster.attrPrimaryEndPointAddress,
        REDIS_PORT: redisCluster.attrPrimaryEndPointPort,
        CI_COMMIT_SHORT_SHA: this.env.commitSHA!,
        DOMAIN_NAME: this.env.domainName!,
        APP_DOMAIN_NAME: this.env.appDomainName!,
        SES_EMAIL_FROM: this.env.sesEmailFrom!,
      },
    };

    taskDefinition.addContainer(
      `${this.resourcePrefix}FargateContainer`,
      container
    );

    const certificate = CM.Certificate.fromCertificateArn(
      this,
      `${this.resourcePrefix}CMCertificate`,
      `arn:aws:acm:${this.env.region}:${this.env.account}:certificate/${this.env.certificateId}`
    );

    const fargateCluster = new ECS.Cluster(
      this,
      `${this.resourcePrefix}FargateCluster`,
      {
        vpc: vpc,
      }
    );

    const fargateService =
      new ECSPatterns.ApplicationLoadBalancedFargateService(
        this,
        `${this.resourcePrefix}APIService`,
        {
          cluster: fargateCluster,
          desiredCount: 3,
          domainName: this.env.domainName,
          domainZone: PublicHostedZone.fromHostedZoneAttributes(
            this,
            `${this.resourcePrefix}FargateLoadBalancerDomainZone`,
            {
              hostedZoneId: this.env.domainZoneId!,
              zoneName: this.env.domainZoneName!,
            }
          ),
          certificate: certificate,
          sslPolicy: SslPolicy.TLS12_EXT,
          protocol: ApplicationProtocol.HTTPS,
          taskDefinition: taskDefinition,
          publicLoadBalancer: true,
          taskSubnets: vpc.selectSubnets({
            subnetType: EC2.SubnetType.PRIVATE_WITH_EGRESS, // hmm...
          }),
          securityGroups: [fargateInternalSecurityGroup],
          platformVersion: ECS.FargatePlatformVersion.LATEST,
        }
      );

    fargateService.targetGroup.configureHealthCheck({
      path: "/common/status",
    });

    fargateService.loadBalancer.addSecurityGroup(fargateExternalSecurityGroup);

    const sourceOutput = new codepipeline.Artifact();
    const transformedOutput = new codepipeline.Artifact();
    const buildProject = new codebuild.PipelineProject(
      this,
      `${this.resourcePrefix}PipelineForAPI`,
      {
        buildSpec: codebuild.BuildSpec.fromObject({
          version: 0.2,
          phases: {
            build: {
              commands: [
                `echo "[{\\"name\\":\\"$CONTAINER_NAME\\",\\"imageUri\\":\\"$REPOSITORY_URI:$IMAGE_TAG\\"}]" > imagedefinitions.json`,
              ],
            },
          },
          artifacts: {
            files: ["imagedefinitions.json"],
          },
        }),
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_2_0,
        },
        environmentVariables: {
          CONTAINER_NAME: {
            value: this.env.appName!,
          },
          REPOSITORY_URI: {
            value: this.dockerImageAssetRepository!.repositoryUri,
          },
          IMAGE_TAG: {
            value: this.env.commitSHA,
          },
        },
      }
    );

    this.dockerImageAssetRepository!.grantPullPush(buildProject.grantPrincipal);

    const codePipeline = new codepipeline.Pipeline(this, `APICodePipeline`, {
      stages: [
        {
          stageName: `APICodeAndDeployPipelineSource`,
          actions: [
            new codepipelineActions.EcrSourceAction({
              actionName: `APIPushAction`,
              repository: this.dockerImageAssetRepository!,
              output: sourceOutput,
            }),
          ],
        },
        {
          stageName: `APICodeAndDeployPipelineBuild`,
          actions: [
            new codepipelineActions.CodeBuildAction({
              actionName: `APIBuildAction`,
              input: sourceOutput,
              outputs: [transformedOutput],
              project: buildProject,
            }),
          ],
        },
        {
          stageName: `APICodeAndDeployPipelineDeploy`,
          actions: [
            new codepipelineActions.EcsDeployAction({
              actionName: `APIDeployAction`,
              input: transformedOutput,
              service: fargateService.service,
            }),
          ],
        },
      ],
    });

    const pipeline = new pipelines.CodePipeline(this, `APIDeployPipeline`, {
      codePipeline: codePipeline,
      synth: new pipelines.ShellStep(`APIDeployStep`, {
        input: pipelines.CodePipelineFileSet.fromArtifact(sourceOutput),
        commands: [
          `aws ecs update-service --service ${fargateService.service.serviceArn} --force-new-deployment true`,
        ],
      }),
    });

    pipeline.buildPipeline();

    pipeline.pipeline.addToRolePolicy(
      new IAM.PolicyStatement({
        sid: `${this.resourcePrefix}APIDeployPipelinePolicyStatement`,
        effect: IAM.Effect.ALLOW,
        actions: ["iam:PassRole", "ecs:UpdateService", "iam:AttachRolePolicy"],
        resources: [fargateService.service.serviceArn],
      })
    );

    const migrationRunnerConstruct = this.addpreDeploymentMigrationLambda(
      redisCluster,
      databaseCluster,
      dbName,
      dbSecret,
      redisSecret,
      encryptionSecret,
      sesSecret,
      vpc
    );

    fargateService.node.addDependency(
      migrationRunnerConstruct,
      databaseCluster,
      redisCluster
    );

    pipeline.node.addDependency(fargateService);
  }

  protected addpreDeploymentMigrationLambda(
    redisCluster: ElastiCache.CfnReplicationGroup,
    databaseCluster: RDS.DatabaseCluster,
    dbName: string,
    dbSecret: SecretsManager.ISecret,
    redisSecret: SecretsManager.ISecret,
    encryptionSecret: SecretsManager.ISecret,
    sesSecret: SecretsManager.ISecret,
    vpc: EC2.Vpc
  ): Construct {
    const lamdbaEnvironment = {
      NODE_ENV: "production",
      DATABASE_HOST: databaseCluster.clusterEndpoint.hostname,
      DATABASE_PORT: databaseCluster.clusterEndpoint.port.toString(),
      DATABASE_DATABASE: dbName,
      REDIS_HOST: redisCluster.attrPrimaryEndPointAddress,
      REDIS_PORT: redisCluster.attrPrimaryEndPointPort,
      DATABASE_SECRET_ARN: dbSecret.secretArn,
      REDIS_SECRET_ARN: redisSecret.secretArn,
      ENCRYPTION_SECRET_ARN: encryptionSecret.secretArn,
      SES_SECRET_ARN: sesSecret.secretArn,
      CI_COMMIT_SHORT_SHA: this.env.commitSHA!,
      DOMAIN_NAME: this.env.domainName!,
      APP_DOMAIN_NAME: this.env.appDomainName!,
      SES_EMAIL_FROM: this.env.sesEmailFrom!,
    };

    const preDeploymentMigrationLambda = new Lambda.Function(
      this,
      `${this.resourcePrefix}MigrationLambda`,
      {
        runtime: Lambda.Runtime.FROM_IMAGE,
        handler: Lambda.Handler.FROM_IMAGE,
        code: Lambda.Code.fromEcrImage(
          this.preDeploymentMigrationLambdaImageAssetRepository!,
          { tagOrDigest: this.env.commitSHA }
        ),
        memorySize: 256,
        timeout: cdk.Duration.minutes(15),
        tracing: Lambda.Tracing.ACTIVE,
        environment: lamdbaEnvironment,
        vpc: vpc,
        vpcSubnets: vpc.selectSubnets({
          subnetType: EC2.SubnetType.PRIVATE_WITH_EGRESS, // hmm...
        }),
      }
    );

    preDeploymentMigrationLambda.node.addDependency(
      databaseCluster,
      redisCluster
    );

    preDeploymentMigrationLambda.grantInvoke(
      new IAM.ServicePrincipal("lambda.amazonaws.com")
    );
    preDeploymentMigrationLambda.currentVersion.grantInvoke(
      new IAM.ServicePrincipal("lambda.amazonaws.com")
    );

    dbSecret.grantRead(preDeploymentMigrationLambda);
    redisSecret.grantRead(preDeploymentMigrationLambda);
    encryptionSecret.grantRead(preDeploymentMigrationLambda);
    sesSecret.grantRead(preDeploymentMigrationLambda);

    const sourceOutput = new codepipeline.Artifact();

    const codePipeline = new codepipeline.Pipeline(
      this,
      `MigrationLambdaCodePipeline`,
      {
        stages: [
          {
            stageName: `MigrationLambdaCodePipelineSource`,
            actions: [
              new codepipelineActions.EcrSourceAction({
                actionName: `LambdaPushAction`,
                repository:
                  this.preDeploymentMigrationLambdaImageAssetRepository!,
                imageTag: this.env.commitSHA,
                output: sourceOutput,
              }),
            ],
          },
        ],
      }
    );

    const pipeline = new pipelines.CodePipeline(
      this,
      `MigrationLambdaDeployPipeline`,
      {
        codePipeline: codePipeline,
        synth: new pipelines.ShellStep(`LambdaDeployStep`, {
          input: pipelines.CodePipelineFileSet.fromArtifact(sourceOutput),
          commands: [
            `aws lambda update-function-code --function-name ${
              preDeploymentMigrationLambda.functionArn
            } --image-uri ${
              this.preDeploymentMigrationLambdaImageAssetRepository!
                .repositoryUri
            }:${this.env.commitSHA} --publish true`,
          ],
        }),
      }
    );

    pipeline.buildPipeline();

    pipeline.pipeline.addToRolePolicy(
      new IAM.PolicyStatement({
        sid: `${this.resourcePrefix}MigrationLambdaDeployPipelinePolicyStatement`,
        effect: IAM.Effect.ALLOW,
        actions: [
          "iam:PassRole",
          "lambda:UpdateFunctionCode",
          "iam:AttachRolePolicy",
        ],
        resources: [preDeploymentMigrationLambda.functionArn],
      })
    );

    pipeline.node.addDependency(preDeploymentMigrationLambda);

    const lamdbaDefinition = {
      service: "Lambda",
      action: "invoke",
      region: this.env.region,
      parameters: {
        FunctionName: preDeploymentMigrationLambda.functionName,
        InvocationType: "Event",
        LogType: "Tail",
        Payload: JSON.stringify({
          command: "runMigrations",
          modifier: !!this.env.dropAndCreate ? "dropAndCreate" : undefined,
        }),
      },
      physicalResourceId: CustomResources.PhysicalResourceId.of(
        `${this.resourcePrefix}TriggerPhysicalId${Math.floor(
          Date.now() / 1000
        )}`
      ),
    };

    const lambdaExecutionRole = new IAM.Role(
      this,
      `${this.resourcePrefix}MigrationLambdaExecutionRole`,
      {
        assumedBy: new IAM.ServicePrincipal("lambda.amazonaws.com"),
        managedPolicies: [
          IAM.ManagedPolicy.fromAwsManagedPolicyName(
            "service-role/AWSLambdaVPCAccessExecutionRole"
          ),
          IAM.ManagedPolicy.fromAwsManagedPolicyName(
            "service-role/AWSLambdaBasicExecutionRole"
          ),
        ],
      }
    );

    const lambdaTrigger = new CustomResources.AwsCustomResource(
      this,
      `${this.resourcePrefix}FunctionTrigger`,
      {
        timeout: cdk.Duration.minutes(15),
        role: lambdaExecutionRole,
        onCreate: lamdbaDefinition,
        onUpdate: lamdbaDefinition,
        policy: CustomResources.AwsCustomResourcePolicy.fromStatements([
          new IAM.PolicyStatement({
            sid: `${this.resourcePrefix}FunctionTriggerPolicyStatement`,
            actions: ["lambda:InvokeFunction"],
            effect: IAM.Effect.ALLOW,
            resources: [preDeploymentMigrationLambda.functionArn],
          }),
        ]),
      }
    );

    preDeploymentMigrationLambda.grantInvoke(lambdaTrigger);

    lambdaTrigger.node.addDependency(pipeline, preDeploymentMigrationLambda);

    return lambdaTrigger;
  }
}
