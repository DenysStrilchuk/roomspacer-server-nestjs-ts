import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';

// Визначаємо тип для конструктора класу
type ClassConstructor<T> = new (...args: any[]) => T;

@Injectable()
export class ValidationPipe<T extends object> implements PipeTransform<T> {
  async transform(value: T, { metatype }: ArgumentMetadata): Promise<T> {
    // Перевірка на валідність типу даних
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    // Преобразування plain об'єкта в екземпляр класу
    const object = plainToInstance(
      metatype as ClassConstructor<T>,
      value as object,
    );
    const errors: ValidationError[] = await validate(object);
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }
    return value;
  }

  private toValidate(metatype: any): boolean {
    const types: Array<ClassConstructor<any>> = [
      String,
      Number,
      Boolean,
      Array,
      Object,
    ];
    return !types.includes(metatype);
  }
}
