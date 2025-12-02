import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response, Request } from 'express';
import { COOKIE_NAME } from './constants';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly config: ConfigService) { }


  @Post("register")
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto)
  }

  @Post("login")
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const tokens = await this.authService.login(dto)

    res.cookie(COOKIE_NAME, tokens.refreshToken, {
      httpOnly: true,
      secure: this.config.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: this.msFromStr(this.config.get('JWT_REFRESH_EXPIRES')),
    })

    return tokens
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rt = req.cookies?.[COOKIE_NAME];
    if (!rt) throw new Error('No refresh token');

    const newTokens = await this.authService.refreshTokens(rt);

    res.cookie(COOKIE_NAME, newTokens.refreshToken, {
      httpOnly: true,
      secure: this.config.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: this.msFromStr(this.config.get('JWT_REFRESH_EXPIRES')),
    });

    return { accessToken: newTokens.accessToken };
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = req.user as any;
    await this.authService.logout(user.id);
    res.clearCookie(COOKIE_NAME);
    return { ok: true };
  }

  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }


  private msFromStr(value?: string): number {
    if (!value) return 7 * 24 * 60 * 60 * 1000;
    const num = parseInt(value.replace(/\D/g, ''), 10);
    if (value.endsWith('s')) return num * 1000;
    if (value.endsWith('m')) return num * 60 * 1000;
    if (value.endsWith('h')) return num * 60 * 60 * 1000;
    if (value.endsWith('d')) return num * 24 * 60 * 60 * 1000;
    return num * 1000;
  }

}
