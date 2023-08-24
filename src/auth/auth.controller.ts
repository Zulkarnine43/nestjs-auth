// src/auth/auth.controller.ts
import { Controller, Req, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Get, UseGuards, Request } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
  ) {}
  @Post('register')
  async register(@Body() body: { username: string; password: string }) {
    const user = await this.authService.register(body.username, body.password);
    return { id: user.id, username: user.username };
  }

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    return this.authService.login(body.username, body.password);
  }

  @Get('user')
  @UseGuards(AuthGuard('jwt'))
  async getCurrentUser(@Req() req: any) {
    return req.user;
  }
}
