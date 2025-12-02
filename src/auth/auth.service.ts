import { BadRequestException, ConflictException, ForbiddenException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import bcrypt from "bcrypt"
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './dto/jwt-payload.interface';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwt: JwtService,
        private readonly config: ConfigService
    ) { }

    async register(dto: RegisterDto) {
        try {
            const { email, password, role, fullName, age, phone } = dto

            const checkUser = await this.prisma.user.findUnique({
                where: {
                    email
                }
            })

            if (checkUser) {
                throw new ConflictException("Bunday email-dagi paydalaniwshi bar!")
            }


            const hashPassword = await this.getHashValue(dto.password)

            return await this.prisma.user.create({
                data: {
                    email,
                    password: hashPassword,
                    role,
                    profile: {
                        create: {
                            fullName, age, phone
                        }
                    }
                },
                select: {
                    email: true,
                    role: true,
                    profile: true
                }
            })

        } catch (error) {
            if (error instanceof ConflictException) {
                throw error
            }

            throw new InternalServerErrorException("Server error")
        }
    }

    async login(dto: LoginDto) {
        try {
            const { email, password } = dto

            const user = await this.prisma.user.findUnique({
                where: {
                    email
                }
            })

            if (!user) {
                throw new ForbiddenException("Email yamasa Password qatelik bar")
            }

            const matchPassword = await bcrypt.compare(password, user.password);

            if (!matchPassword) {
                throw new ForbiddenException("Email yamasa Password qatelik bar")
            }

            const { accessToken, refreshToken } = await this.generateTokenAndSave({ sub: user.id, email: user.email })

            return {
                accessToken, refreshToken, user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                }
            }
        } catch (error) {

            if (error instanceof ForbiddenException) {
                throw error
            }

            throw new InternalServerErrorException("Server error")
        }
    }

    async refreshTokens(refreshToken: string) {
        let payload: JwtPayload;

        try {
            payload = await this.jwt.verifyAsync<JwtPayload>(refreshToken, {
                secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
            });
        } catch (err) {
            throw new ForbiddenException('Invalid or expired refresh token');
        }

        const userId = payload.sub;
        if (!userId) throw new BadRequestException('Refresh token payload missing sub');

        const tokensInDb = await this.prisma.token.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: 10,
        });

        if (!tokensInDb || tokensInDb.length === 0) {
            throw new ForbiddenException('No refresh token found for user');
        }

        let matchedTokenRecord: any = null;
        for (const rec of tokensInDb) {
            const isMatch = await bcrypt.compare(refreshToken, rec.token);
            if (isMatch) {
                matchedTokenRecord = rec;
                break;
            }
        }

        if (!matchedTokenRecord) {
            throw new ForbiddenException('Refresh token is invalid or revoked');
        }

        await this.prisma.token.delete({ where: { id: matchedTokenRecord.id } });

        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new ForbiddenException('User not found');

        const newTokens = await this.generateTokenAndSave({ sub: user.id, email: user.email });
        const newHashed = await this.getHashValue(newTokens.refreshToken);

        await this.prisma.token.create({
            data: {
                token: newHashed,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                userId: user.id,
            },
        });

        return newTokens;

    }

    async logout(userId: number) {
        await this.prisma.token.deleteMany({
            where: {
                userId
            }
        })

        return { ok: true };
    }

    async getHashValue(val: string) {
        const salt = await bcrypt.genSalt()
        return await bcrypt.hash(val, salt)
    }

    async generateTokenAndSave(dto: JwtPayload) {
        const accessToken = await this.jwt.signAsync(dto, {
            secret: this.config.get<string>('JWT_ACCESS_SECRET'),
            expiresIn: this.config.get<number>('JWT_ACCESS_EXPIRES'),
        })

        const refreshToken = await this.jwt.signAsync(dto, {
            secret: this.config.get<string>('JWT_REFRESH_SECRET'),
            expiresIn: this.config.get<number>('JWT_REFRESH_EXPIRES'),
        })

        const hashToken = await this.getHashValue(refreshToken)

        await this.prisma.token.create({
            data: {
                token: hashToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                userId: dto.sub
            }
        })

        return {
            accessToken, refreshToken
        }
    }
}
