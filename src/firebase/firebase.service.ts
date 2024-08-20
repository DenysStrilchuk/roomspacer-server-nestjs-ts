import { Injectable, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FirebaseService {
  private static firebaseApp: admin.app.App;

  constructor(private readonly configService: ConfigService) {
    this.initializeFirebaseApp();
  }

  private initializeFirebaseApp() {
    if (!FirebaseService.firebaseApp) {
      try {
        FirebaseService.firebaseApp = admin.initializeApp({
          credential: admin.credential.cert({
            projectId: this.configService.get<string>('FIREBASE_PROJECT_ID'),
            privateKey: this.configService
              .get<string>('FIREBASE_PRIVATE_KEY')
              .replace(/\\n/g, '\n'),
            clientEmail: this.configService.get<string>(
              'FIREBASE_CLIENT_EMAIL',
            ),
          }),
        });
        Logger.log('Firebase app initialized');
      } catch (error) {
        Logger.error('Error initializing Firebase app', error);
      }
    } else {
      Logger.log('Firebase app already initialized');
    }
  }

  getAuth() {
    return FirebaseService.firebaseApp.auth();
  }

  getFirestore() {
    return admin.firestore();
  }

  async verifyIdToken(idToken: string): Promise<admin.auth.DecodedIdToken> {
    try {
      return await this.getAuth().verifyIdToken(idToken);
    } catch (error) {
      Logger.error('Error verifying ID token', error);
      throw error;
    }
  }
}
