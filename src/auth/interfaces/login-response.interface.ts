export interface ILoginResponse {
  user: {
    uid: string;
    email: string;
    name?: string;
    picture?: string;
  };
  token: string;
}
