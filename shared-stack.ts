import { BaseStack } from "./base-stack";
import * as EC2 from "aws-cdk-lib/aws-ec2";

export class SharedStack extends BaseStack {
  createResources(): void {
    this.vpc = new EC2.Vpc(this, `${this.resourcePrefix}VPC`, {
      maxAzs: 2,
    });
  }
}
