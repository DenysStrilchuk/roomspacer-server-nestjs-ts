import { Injectable } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class FirebaseService {
  private defaultApp: admin.app.App;
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    if (admin.apps.length === 0) {
      const serviceAccount = {
        type: this.configService.get<string>('FIREBASE_TYPE'),
        project_id: this.configService.get<string>('FIREBASE_PROJECT_ID'),
        private_key_id: this.configService.get<string>(
          'FIREBASE_PRIVATE_KEY_ID',
        ),
        private_key: this.configService
          .get<string>('FIREBASE_PRIVATE_KEY')
          .replace(/\\n/g, '\n'),
        client_email: this.configService.get<string>('FIREBASE_CLIENT_EMAIL'),
        client_id: this.configService.get<string>('FIREBASE_CLIENT_ID'),
        auth_uri: this.configService.get<string>('FIREBASE_AUTH_URI'),
        token_uri: this.configService.get<string>('FIREBASE_TOKEN_URI'),
        auth_provider_x509_cert_url: this.configService.get<string>(
          'FIREBASE_AUTH_PROVIDER_CERT_URL',
        ),
        client_x509_cert_url: this.configService.get<string>(
          'FIREBASE_CLIENT_CERT_URL',
        ),
      };

      this.defaultApp = admin.initializeApp({
        credential: admin.credential.cert(
          serviceAccount as admin.ServiceAccount,
        ),
        databaseURL: this.configService.get<string>('FIREBASE_DATABASE_URL'),
      });
    } else {
      this.defaultApp = admin.apps[0];
    }

    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: this.configService.get<string>('EMAIL_USER'),
        pass: this.configService.get<string>('EMAIL_PASS'),
      },
    });
  }

  getAuth() {
    return this.defaultApp.auth();
  }

  getFirestore() {
    const firestore = this.defaultApp.firestore();
    firestore.settings({
      requestTimeout: 120000,
    });
    return firestore;
  }

  async sendEmail(to: string, subject: string, text: string): Promise<void> {
    const mailOptions = {
      from: this.configService.get<string>('EMAIL_USER'),
      to,
      subject,
      text,
    };

    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Error sending email:', error);
    }
  }

  async sendEmailVerification(userId: string): Promise<void> {
    const user = await this.getAuth().getUser(userId);
    const link = await this.getAuth().generateEmailVerificationLink(user.email);
    await this.sendEmail(
      user.email,
      'Email Verification',
      `Verify your email: ${link}`,
    );
  }

  async sendPasswordResetEmail(email: string): Promise<void> {
    const user = await this.getAuth().getUserByEmail(email);
    const token = await this.getAuth().createCustomToken(user.uid);
    const resetPasswordUrl = `http://localhost:3000/auth/reset-password/${token}`;

    await this.sendEmail(
      email,
      'Password Reset',
      `Reset your password by clicking the following link: ${resetPasswordUrl}`,
    );
  }

  async verifyIdToken(token: string): Promise<admin.auth.DecodedIdToken> {
    return await this.getAuth().verifyIdToken(token);
  }

  async sendEmailChangeVerification(
    userId: string,
    newEmail: string,
  ): Promise<void> {
    await this.getAuth().updateUser(userId, { email: newEmail });
    await this.sendEmailVerification(userId);
  }
}
