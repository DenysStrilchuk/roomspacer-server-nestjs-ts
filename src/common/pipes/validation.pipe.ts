import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';

@Injectable()
export class ValidationPipe<T> implements PipeTransform<T> {
  async transform(value: T, { metatype }: ArgumentMetadata): Promise<T> {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    const object = plainToInstance(metatype as any, value);
    const errors: ValidationError[] = await validate(object);
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }
    return value;
  }

  private toValidate(metatype: any): boolean {
    const types = [String, Number, Boolean, Array, Object];
    return !types.includes(metatype);
  }
}
