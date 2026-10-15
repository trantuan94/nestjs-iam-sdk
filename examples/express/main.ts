import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { ExampleAppModule, optionsFromEnv } from '../shared/app.module';

// IAM_BASE_URL=http://localhost:3000/api/iam IAM_API_KEY=iam_… npx ts-node examples/express/main.ts
async function main() {
  const app = await NestFactory.create(ExampleAppModule.with(optionsFromEnv()));
  await app.listen(Number(process.env.PORT ?? 4000));
}
void main();
