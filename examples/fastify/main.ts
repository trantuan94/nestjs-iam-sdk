import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import { ExampleAppModule, optionsFromEnv } from '../shared/app.module';

// IAM_BASE_URL=http://localhost:3000/api/iam IAM_API_KEY=iam_… npx ts-node examples/fastify/main.ts
async function main() {
  const app = await NestFactory.create<NestFastifyApplication>(
    ExampleAppModule.with(optionsFromEnv()),
    new FastifyAdapter(),
  );
  await app.listen(Number(process.env.PORT ?? 4001), '0.0.0.0');
}
void main();
