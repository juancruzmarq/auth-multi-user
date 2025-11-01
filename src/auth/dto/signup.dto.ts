import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class SignupDto {
  @IsEmail({}, { message: 'email must be a valid email address' })
  @IsString()
  email!: string;

  @MinLength(8)
  @IsString({ message: 'password must be at least 8 characters long' })
  password!: string;

  @IsNotEmpty({ message: 'name is required' })
  @IsString({ message: 'name must be a string' })
  name!: string;
}
