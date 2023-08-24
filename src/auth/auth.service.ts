// src/auth/auth.service.ts
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user.entity';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  public _createToken({ username }): any {
    const user = { username: username };
    const accessToken = this.jwtService.sign(user);
    return {
      expires_in: 860000,
      token: accessToken,
      token_type: 'bearer',
    };
  }

  async register(username: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = this.userRepository.create({
      username,
      password: hashedPassword,
    });
    return this.userRepository.save(user);
  }

  async login(username: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: { username }, // Use the 'where' property of FindOneOptions
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
    }

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = this._createToken(user);
      const userData = {
        id: user.id,
        username: user.username,
      };
      return {
        user: userData,
        ...token,
      };
    } else {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }

  async validate(payload: any) {
    const username = payload.username;
    const user = await this.userRepository.findOne({
      where: { username },
    });

    if (!user) {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }
    const userData = {
      id: user.id,
      username: user.username,
    };
    return userData;
  }
}
