import { Injectable } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FirebaseService {
  private static firebaseApp: admin.app.App;

  constructor(private readonly configService: ConfigService) {
    if (!FirebaseService.firebaseApp) {
      FirebaseService.firebaseApp = admin.initializeApp({
        credential: admin.credential.cert({
          projectId: this.configService.get<string>('FIREBASE_PROJECT_ID'),
          privateKey: this.configService
            .get<string>('FIREBASE_PRIVATE_KEY')
            .replace(/\\n/g, '\n'),
          clientEmail: this.configService.get<string>('FIREBASE_CLIENT_EMAIL'),
        }),
      });
    }
  }

  getAuth() {
    return FirebaseService.firebaseApp.auth();
  }
}
