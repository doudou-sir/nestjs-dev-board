import { IsString, IsOptional, IsArray } from 'class-validator';

export class ProfileDto {
  @IsString()
  @IsOptional() // 非必传
  avatar?: string;

  @IsString()
  @IsOptional() // 非必传
  phone?: string;

  @IsString()
  @IsOptional() // 非必传
  status?: number;

  @IsArray()
  @IsOptional() // 非必传
  address?: string;

  @IsOptional()
  longitude?: number;

  @IsOptional()
  latitude?: number;

  @IsOptional()
  gender?: number;

  @IsString()
  @IsOptional()
  birthday?: string;

  @IsString()
  @IsOptional()
  motto?: string;

  @IsOptional()
  grade?: number;
}
