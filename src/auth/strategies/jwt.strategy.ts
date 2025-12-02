import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly prisma: PrismaService, private readonly config: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.getOrThrow<string>("JWT_ACCESS_SECRET")
        });
    }

    

    async validate(payload: any) {
        const user = await this.prisma.user.findUnique({ where: { id: payload.sub } });
        if (!user) return null;
        return { id: user.id, email: user.email, role: user.role };
    }
}
