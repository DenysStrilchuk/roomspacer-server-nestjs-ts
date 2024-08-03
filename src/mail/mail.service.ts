import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('EMAIL_HOST'),
      port: parseInt(this.configService.get<string>('EMAIL_PORT')),
      secure: this.configService.get<string>('EMAIL_SECURE') === 'true',
      auth: {
        user: this.configService.get<string>('EMAIL_USER'),
        pass: this.configService.get<string>('EMAIL_PASS'),
      },
    });
  }

  async sendConfirmationEmail(to: string, verificationLink: string) {
    const mailOptions = {
      from: '"Roomspacer" <roomspacerapp@gmail.com>',
      to,
      subject: 'Email Confirmation',
      html: `<p>Please confirm your email by clicking the following link:</p><p><a href="${verificationLink}">${verificationLink}</a></p>`,
    };

    await this.transporter.sendMail(mailOptions);
  }
}
