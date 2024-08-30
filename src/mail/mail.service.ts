import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import * as process from 'process';

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

  async sendConfirmationEmail(
    to: string,
    name: string,
    verificationLink: string,
  ) {
    const templatePath = path.resolve(
      process.cwd(),
      'src',
      'templates',
      'confirmation-email.template.html',
    );
    let htmlContent = fs.readFileSync(templatePath, 'utf8');

    // Заміняємо змінні у шаблоні
    htmlContent = htmlContent.replace('{{ name }}', name);
    htmlContent = htmlContent.replace(
      '{{ verificationLink }}',
      verificationLink,
    );

    const mailOptions = {
      from: '"Roomspacer" <roomspacerapp@gmail.com>',
      to,
      subject: 'Email Confirmation',
      html: htmlContent,
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendResetPasswordEmail(to: string, resetLink: string) {
    const templatePath = path.resolve(
      process.cwd(),
      'src',
      'templates',
      'reset-password-email.template.html',
    );
    let htmlContent = fs.readFileSync(templatePath, 'utf8');

    htmlContent = htmlContent.replace('{{ resetLink }}', resetLink);

    const mailOptions = {
      from: '"Roomspacer" <roomspacerapp@gmail.com>',
      to,
      subject: 'Password Reset',
      html: htmlContent,
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendInvitationEmail(to: string, invitationLink: string) {
    const templatePath = path.resolve(
      process.cwd(),
      'src',
      'templates',
      'invitation-email.template.html',
    );
    let htmlContent = fs.readFileSync(templatePath, 'utf8');

    htmlContent = htmlContent.replace('{{ invitationLink }}', invitationLink);

    const mailOptions = {
      from: '"Roomspacer" <roomspacerapp@gmail.com>',
      to,
      subject: 'Invitation to Roomspacer',
      html: htmlContent,
    };

    await this.transporter.sendMail(mailOptions);
  }
}
