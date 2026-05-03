import JWT from "jsonwebtoken";

export interface JWTClaims {
  iss: string;
  sub: string;
  aud: string;
  email: string;
  email_verified: boolean;
  exp: number;
  family_name?: string;
  given_name: string;
  name: string;
  picture?: string;
}
