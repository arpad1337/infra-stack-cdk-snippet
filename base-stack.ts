import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import * as EC2 from "aws-cdk-lib/aws-ec2";

export type ExtendedStackProps = cdk.StackProps & {
  env: {
    account: string | undefined;
    region: string | undefined;
    appName: string | undefined;
    appDomainName: string | undefined;
    sesEmailFrom: string | undefined;
    certificateId: string | undefined;
    domainName: string | undefined;
    domainZoneId: string | undefined;
    domainZoneName: string | undefined;
    session: string | undefined;
    lambdaAppName: string | undefined;
    commitSHA: string | undefined;
    dropAndCreate: boolean;
  };
};

export interface ICurrentUser {
  Account: string;
  UserId: string;
  Arn: string;
}

export abstract class BaseStack extends cdk.Stack {
  private _resourcePrefix: string;
  private _env: ExtendedStackProps["env"];

  protected get resourcePrefix(): string {
    return this._resourcePrefix;
  }

  protected get env(): ExtendedStackProps["env"] {
    return this._env;
  }

  protected get _preDeploymentMigrationLambdaRepositorName():
    | string
    | undefined {
    return this.env.lambdaAppName;
  }

  protected vpc: EC2.Vpc | undefined = undefined;

  setVPC(vpc: EC2.Vpc): void {
    this.vpc = vpc;
  }

  getVPC(): EC2.Vpc | undefined {
    return this.vpc;
  }

  protected get currentUser(): ICurrentUser | undefined {
    return (this.env.session && JSON.parse(this.env.session)) || undefined;
  }

  constructor(
    app: Construct,
    resourcePrefix: string,
    props: ExtendedStackProps
  ) {
    super(app, `${resourcePrefix}Stack`, props);
    this._resourcePrefix = resourcePrefix;
    this._env = props.env;
  }

  abstract createResources(): void;
}
