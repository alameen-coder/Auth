import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignUpDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SigninDto } from './dto/signin.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  signToken(userId: number, email: string): Promise<string> {
    const payload = { sub: userId, email };
    return this.jwt.signAsync(payload);
  }
  async signup(dto: SignUpDto): Promise<{ access_token: string }> {
    try {
      if (!dto.email || !dto.password) {
        throw new Error('Email and password are required');
      }

      const hashedPassword = await bcrypt.hash(dto.password, 10);

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
        },
      });

      const token = await this.signToken(user.id, user.email);
      if (!token) {
        throw new Error('Failed to generate JWT token');
      }

      return {
        access_token: token,
      };
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        (error as any).code === 'P2002'
      ) {
        throw new Error('Email already exists');
      }
      throw error;
    }
  }

  async login(dto: SigninDto): Promise<{ access_token: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    // const passwordHash = await bcrypt.hash(dto.password, 10);
    const pwMatches = await bcrypt.compare(dto.password, user.password);

    if (!pwMatches) {
      throw new ForbiddenException('Invalid password');
    }

    const token = await this.signToken(user.id, user.email);
    if (!token) {
      throw new Error('Failed to generate JWT token');
    }

    return {
      access_token: token,
    };
  }
}
