import { Role } from "@prisma/client";
import { IsEmail, IsEnum, IsNotEmpty, IsNumber, IsString, Length, Matches, MaxLength, MinLength } from "class-validator";

export class RegisterDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password cannot exceed 20 characters' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/, {
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    })
    password: string;

    @IsEnum(Role)
    @IsNotEmpty()
    role: Role

    @IsString()
    @IsNotEmpty()
    fullName: string

    @IsString()
    @IsNotEmpty()
    phone: string

    @IsNumber()
    @IsNotEmpty()
    age: number;
}