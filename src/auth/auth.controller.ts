// src/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Get, Req, UseGuards, Request } from '@nestjs/common';
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
  @UseGuards(AuthGuard('local'))
  async login(@Request() req) {
    return req.user;
    // if (!user) {
    //   throw new UnauthorizedException('Invalid credentials');
    // }
    // const payload = { username: user.username, sub: user.id };
    // const accessToken = await this.jwtService.signAsync(payload);
    // return { access_token: accessToken };
  }
}
