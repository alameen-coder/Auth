import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import { JwtGuard as JwtAuthGuard } from './guard/jwt.guard';

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
  @UseGuards(JwtAuthGuard)
  @Delete('delete')
  deleteUser(@Req() req: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
    return this.authservice.deleteUser(req.user.sub);
  }
  // @UseGuards(JwtAuthGuard)
  // @Post('referesh')
  // refereshToken(@Req() req: any) {
  //   // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
  //   return this.authservice.refereshToken(req.user.sub, req.user.email);
  // }
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
    return req.user;
  }
  @Post('ping')
  @HttpCode(200)
  ping() {
    console.log('🔊 Ping route hit');
    return { message: 'pong' };
  }
}
