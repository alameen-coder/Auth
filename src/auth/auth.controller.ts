import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authservice: AuthService) {}

  @Post('signup')
  signup(@Body() dto: SignUpDto) {
    return this.authservice.signup(dto);
  }
  @Post('login')
  login(@Body() dto: SigninDto) {
    return this.authservice.login(dto);
  }
  @Post('ping')
  @HttpCode(200)
  ping() {
    console.log('🔊 Ping route hit');
    return { message: 'pong' };
  }
}
