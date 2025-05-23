import { BaseStack } from "./base-stack";
import * as ECR from "aws-cdk-lib/aws-ecr";

export class ECRRepoStack extends BaseStack {
  protected dockerImageRepository: ECR.IRepository | undefined = undefined;

  getAPIRepository(): ECR.IRepository | undefined {
    return this.dockerImageRepository;
  }

  protected preDeploymentMigrationLambdaImageRepository:
    | ECR.IRepository
    | undefined = undefined;

  getPreDeploymentMigrationLambdaRepository(): ECR.IRepository | undefined {
    return this.preDeploymentMigrationLambdaImageRepository;
  }

  createResources(): void {
    const dockerImageRepository = ECR.Repository.fromRepositoryAttributes(
      this,
      `${this.resourcePrefix}ECRRepositoryAPI`,
      {
        repositoryArn: ECR.Repository.arnForLocalRepository(
          this.env.appName!,
          this
        ),
        repositoryName: this.env.appName!,
      }
    );

    this.dockerImageRepository = dockerImageRepository;

    const preDeploymentMigrationLambdaImageRepository =
      ECR.Repository.fromRepositoryAttributes(
        this,
        `${this.resourcePrefix}ECRRepositorypreDeploymentMigrationLambda`,
        {
          repositoryArn: ECR.Repository.arnForLocalRepository(
            this._preDeploymentMigrationLambdaRepositorName!,
            this
          ),
          repositoryName: this._preDeploymentMigrationLambdaRepositorName!,
        }
      );

    this.preDeploymentMigrationLambdaImageRepository =
      preDeploymentMigrationLambdaImageRepository;
  }
}
