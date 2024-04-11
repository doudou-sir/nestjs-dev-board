export type SetTokensData = {
  accessToken: string;
  refreshToken: string;
};

export type JwtPayload = {
  sub: number;
  email: string;
  role: number;
};

export type JwtRefreshPayload = {
  sub: number;
};
